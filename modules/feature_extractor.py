"""
Volatility 3 feature extractor for Windows memory dumps.

Runs five plugins against a single shared context:
  PsList   → process enumeration via EPROCESS linked list
  PsScan   → process enumeration via pool-tag scanning (detects DKOM hiding)
  DllList  → per-process loaded modules
  VadInfo  → virtual address descriptor tree (memory region permissions)
  Malfind  → VAD regions with executable+private flags (injection candidates)

Returns one dictionary ready for INSERT into the features.feature_data JSONB column.
"""

import concurrent.futures
import logging
import math
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ── Windows memory protection strings that indicate write+execute ─────────────
_RWX_PROTECTIONS = frozenset({
    "PAGE_EXECUTE_READWRITE",
    "PAGE_EXECUTE_WRITECOPY",
})

# ── Path fragments that indicate a legitimate system DLL ──────────────────────
_TRUSTED_PATH_PREFIXES = (
    "\\windows\\",
    "\\program files\\",
    "\\program files (x86)\\",
)

# ── Path fragments used by malware to stage injected DLLs ────────────────────
_SUSPICIOUS_PATH_FRAGMENTS = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\desktop\\",
    "$recycle",       # C:\$Recycle.Bin\...
    "\\perflogs\\",
)

# ── High-entropy threshold (packed / encrypted code heuristic) ────────────────
_HIGH_ENTROPY_THRESHOLD = 7.0


# ─────────────────────────────────────────────────────────────────────────────
# Pure-Python helpers (no vol3 dependency)
# ─────────────────────────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence, rounded to 4 decimal places."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)


def _has_pe_header(data: bytes) -> bool:
    return len(data) >= 2 and data[:2] == b"MZ"


def _is_suspicious_dll_path(path: str | None) -> bool:
    """
    Return True when the DLL path is absent (reflective injection) or
    originates from a user-writable staging location.
    """
    if not path:
        return True
    lower = path.lower()
    if any(lower.find(t) != -1 for t in _TRUSTED_PATH_PREFIXES):
        return False
    return any(lower.find(s) != -1 for s in _SUSPICIOUS_PATH_FRAGMENTS)


def _risk_score(
    hidden: int,
    malfind_hits: int,
    rwx_regions: int,
    suspicious_dlls: int,
) -> float:
    """
    Composite 0.0–1.0 maliciousness heuristic.
    Each category is capped so no single signal can dominate.
    """
    score = 0.0
    score += min(0.35, hidden        * 0.15)   # DKOM hiding is a strong indicator
    score += min(0.30, malfind_hits  * 0.08)   # injected executable regions
    score += min(0.20, max(0, rwx_regions - 3) * 0.04)  # abnormal RWX count
    score += min(0.15, suspicious_dlls * 0.05)
    return round(min(1.0, score), 4)


# ─────────────────────────────────────────────────────────────────────────────
# Volatility 3 value normaliser
# ─────────────────────────────────────────────────────────────────────────────

def _safe(val: Any) -> Any:
    """
    Convert every Volatility 3 result type to a plain JSON-serialisable value.

    Types handled:
      BaseAbsentValue subclasses  → None
      format_hints.Hex            → "0x..." string
      format_hints.HexBytes       → bytes (caller decides how to use)
      renderers.LayerData         → bytes read from the memory layer
      renderers.Disassembly       → str of disassembly text
      datetime                    → ISO 8601 string
    """
    try:
        from volatility3.framework.interfaces.renderers import BaseAbsentValue
        from volatility3.framework.renderers import LayerData, Disassembly
        from volatility3.framework.renderers.format_hints import Hex, HexBytes
    except ImportError:
        return val

    if isinstance(val, BaseAbsentValue):
        return None
    if isinstance(val, LayerData):
        try:
            return val.context.layers[val.layer_name].read(val.offset, val.length, True)
        except Exception:
            return None
    if isinstance(val, Disassembly):
        return str(val)
    if isinstance(val, HexBytes):
        return bytes(val)
    if isinstance(val, Hex):
        return hex(int(val))
    if isinstance(val, datetime):
        return val.isoformat()
    return val


# ─────────────────────────────────────────────────────────────────────────────
# FeatureExtractor
# ─────────────────────────────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Extract forensic features from a Windows memory dump via Volatility 3.

    All five plugin runs share a single context so the memory image is stacked
    (parsed) only once.  Each plugin failure is isolated — it appends to
    self.errors and returns empty data rather than aborting the whole pipeline.
    """

    def __init__(self, dump_path: str) -> None:
        if not os.path.isfile(dump_path):
            raise FileNotFoundError(f"Memory dump not found: {dump_path}")
        self._dump_path = os.path.abspath(dump_path)
        self._ctx = None
        self._automagics = None
        self.errors: list[str] = []
        self._setup()

    # ── Volatility 3 initialisation ───────────────────────────────────────────

    def _setup(self) -> None:
        try:
            import volatility3.framework as vf
            import volatility3.plugins as vp
            from volatility3.framework import automagic, contexts
        except ImportError as exc:
            raise RuntimeError(
                "volatility3 is not installed. Run: pip install volatility3"
            ) from exc

        # Import all built-in plugins so automagic can satisfy requirements.
        vf.import_files(vp, ignore_errors=True)

        self._ctx = contexts.Context()
        self._ctx.config["automagic.LayerStacker.single_location"] = (
            f"file://{self._dump_path}"
        )
        self._automagics = automagic.available(self._ctx)

    # Seconds each plugin may run before being skipped with partial results.
    PLUGIN_TIMEOUT = 180

    def _run_plugin(self, plugin_class) -> list[dict]:
        """
        Construct and run one plugin against the shared context.
        Returns a list of row dicts with normalised Python values.
        Times out after PLUGIN_TIMEOUT seconds so a slow plugin cannot stall the pipeline.
        """
        from volatility3.framework import plugins as fp

        def _execute() -> list[dict]:
            constructed = fp.construct_plugin(
                self._ctx, self._automagics, plugin_class,
                "plugins", None, None,
            )
            treegrid = constructed.run()
            col_names = [col.name for col in treegrid.columns]
            rows: list[dict] = []

            def _visitor(node, accumulator):
                accumulator.append(
                    {name: _safe(val) for name, val in zip(col_names, node.values)}
                )
                return accumulator

            treegrid.visit(None, _visitor, rows)
            return rows

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_execute)
                return future.result(timeout=self.PLUGIN_TIMEOUT)
        except concurrent.futures.TimeoutError:
            msg = (
                f"{plugin_class.__name__}: TimeoutError: "
                f"plugin exceeded {self.PLUGIN_TIMEOUT}s limit — skipped"
            )
            self.errors.append(msg)
            logger.warning("Plugin timed out — %s", msg)
            return []
        except Exception as exc:
            msg = f"{plugin_class.__name__}: {type(exc).__name__}: {exc}"
            self.errors.append(msg)
            logger.warning("Plugin run failed — %s", msg)
            return []

    # ── Process features ──────────────────────────────────────────────────────

    def extract_process_features(self) -> dict:
        """
        Compare PsList (linked-list walk) vs PsScan (pool-tag scan) to surface
        processes that have been unlinked from the EPROCESS list (DKOM hiding).
        """
        from volatility3.plugins.windows import pslist, psscan

        listed_rows = self._run_plugin(pslist.PsList)
        scanned_rows = self._run_plugin(psscan.PsScan)

        listed_pids: set[int] = set()
        processes: list[dict] = []

        for row in listed_rows:
            pid = row.get("PID")
            if pid is None:
                continue
            listed_pids.add(pid)
            processes.append({
                "pid":           pid,
                "ppid":          row.get("PPID"),
                "name":          row.get("ImageFileName"),
                "threads":       row.get("Threads"),
                "handles":       row.get("Handles"),
                "session_id":    row.get("SessionId"),
                "wow64":         row.get("Wow64"),
                "create_time":   row.get("CreateTime"),
                "exit_time":     row.get("ExitTime"),
                "is_hidden":     False,
            })

        # Processes found by pool scan but absent from the linked list.
        hidden: list[dict] = []
        for row in scanned_rows:
            pid = row.get("PID")
            if pid is None or pid in listed_pids:
                continue
            entry = {
                "pid":         pid,
                "ppid":        row.get("PPID"),
                "name":        row.get("ImageFileName"),
                "threads":     row.get("Threads"),
                "handles":     row.get("Handles"),
                "session_id":  row.get("SessionId"),
                "wow64":       row.get("Wow64"),
                "create_time": row.get("CreateTime"),
                "exit_time":   row.get("ExitTime"),
                "is_hidden":   True,
            }
            hidden.append(entry)
            processes.append(entry)

        # Build parent→[children] map using string keys (JSON-safe).
        parent_child_map: dict[str, list[str]] = {}
        for p in processes:
            ppid = str(p["ppid"]) if p["ppid"] is not None else "0"
            pid  = str(p["pid"])
            parent_child_map.setdefault(ppid, []).append(pid)

        return {
            "total_count":       len(processes),
            "hidden_count":      len(hidden),
            "processes":         processes,
            "parent_child_map":  parent_child_map,
        }

    # ── DLL features ──────────────────────────────────────────────────────────

    def extract_dll_features(self) -> dict:
        """
        Enumerate per-process loaded modules.  Flags DLLs with no path
        (reflective injection) or loaded from user-writable staging directories.
        """
        from volatility3.plugins.windows import dlllist

        rows = self._run_plugin(dlllist.DllList)

        dlls: list[dict] = []
        suspicious_names: list[str] = []

        for row in rows:
            path       = row.get("Path") or ""
            name       = row.get("Name") or ""
            suspicious = _is_suspicious_dll_path(path or None)

            entry = {
                "pid":            row.get("PID"),
                "process_name":   row.get("Process"),
                "dll_name":       name,
                "dll_path":       path,
                "base_address":   row.get("Base"),    # hex string via _safe
                "size":           row.get("Size"),    # hex string via _safe
                "load_count":     row.get("LoadCount"),
                "load_time":      row.get("LoadTime"),
                "is_suspicious":  suspicious,
            }
            dlls.append(entry)
            if suspicious and name:
                suspicious_names.append(name)

        return {
            "total_loaded":           len(dlls),
            "unsigned_count":         0,          # requires PE signature checks; placeholder
            "suspicious_paths_count": sum(1 for d in dlls if d["is_suspicious"]),
            "dlls":                   dlls,
            "suspicious_dll_names":   list(set(suspicious_names)),
        }

    # ── Memory region features ────────────────────────────────────────────────

    def extract_memory_region_features(self) -> dict:
        """
        Walk the VAD tree for all processes.  Highlights regions with
        write+execute permissions and large private-executable allocations
        (common shellcode / reflective-loader staging patterns).
        """
        from volatility3.plugins.windows import vadinfo

        rows = self._run_plugin(vadinfo.VadInfo)

        regions: list[dict] = []
        rwx_count = 0
        suspicious_count = 0

        for row in rows:
            protection   = row.get("Protection") or ""
            is_rwx       = protection.upper() in _RWX_PROTECTIONS
            private_mem  = bool(row.get("PrivateMemory"))

            start_raw = row.get("Start VPN")
            end_raw   = row.get("End VPN")

            # Compute byte size from VPN addresses (still hex strings at this point).
            try:
                start_int = int(start_raw, 16) if isinstance(start_raw, str) else int(start_raw or 0)
                end_int   = int(end_raw,   16) if isinstance(end_raw,   str) else int(end_raw   or 0)
                region_size = end_int - start_int + 1
            except (TypeError, ValueError):
                region_size = None

            # Suspicious: RWX, or large (>1 MiB) private executable region.
            is_suspicious = is_rwx or (
                private_mem
                and "EXECUTE" in protection.upper()
                and region_size is not None
                and region_size > 1_048_576
            )

            entry = {
                "pid":            row.get("PID"),
                "process_name":   row.get("Process"),
                "start_address":  start_raw,
                "end_address":    end_raw,
                "size_bytes":     region_size,
                "tag":            row.get("Tag"),
                "protection":     protection,
                "commit_charge":  row.get("CommitCharge"),
                "private_memory": private_mem,
                "is_rwx":         is_rwx,
                "is_suspicious":  is_suspicious,
            }
            regions.append(entry)
            if is_rwx:
                rwx_count += 1
            if is_suspicious:
                suspicious_count += 1

        return {
            "total_regions":         len(regions),
            "rwx_count":             rwx_count,
            "suspicious_allocations": suspicious_count,
            "regions":               regions,
        }

    # ── Behavioral indicators ─────────────────────────────────────────────────

    def extract_behavioral_indicators(self) -> dict:
        """
        Run Malfind to enumerate executable+private VAD regions that exhibit
        code-injection signatures.  For each hit, reads the raw bytes from the
        memory layer to compute Shannon entropy and detect embedded PE headers.
        """
        try:
            from volatility3.plugins.windows.malware import malfind
        except ImportError:
            # Fallback for older vol3 layouts.
            from volatility3.plugins.windows import malfind  # type: ignore[no-redef]

        rows = self._run_plugin(malfind.Malfind)

        injections: list[dict] = []
        high_entropy_count = 0

        for row in rows:
            raw_bytes = row.get("Hexdump")      # bytes via _safe(LayerData)
            if not isinstance(raw_bytes, bytes):
                raw_bytes = b""

            ent         = _entropy(raw_bytes)
            pe_header   = _has_pe_header(raw_bytes)
            is_high_ent = ent >= _HIGH_ENTROPY_THRESHOLD

            if is_high_ent:
                high_entropy_count += 1

            injections.append({
                "pid":           row.get("PID"),
                "process_name":  row.get("Process"),
                "start_address": row.get("Start VPN"),
                "end_address":   row.get("End VPN"),
                "tag":           row.get("Tag"),
                "protection":    row.get("Protection"),
                "commit_charge": row.get("CommitCharge"),
                "private_memory": bool(row.get("PrivateMemory")),
                "notes":         row.get("Notes"),
                "entropy":       ent,
                "has_pe_header": pe_header,
                "hex_preview":   raw_bytes[:64].hex() if raw_bytes else None,
                "disassembly":   row.get("Disasm"),
            })

        hit_count = len(injections)

        # Injection confidence: weighted presence of PE headers and high entropy.
        pe_hits = sum(1 for i in injections if i["has_pe_header"])
        injection_score = round(
            min(1.0, (pe_hits * 0.25) + (high_entropy_count * 0.15)), 4
        )

        return {
            "malfind_count":       hit_count,
            "high_entropy_regions": high_entropy_count,
            "injection_score":     injection_score,
            "injection_evidence":  injections,
        }

    # ── Full pipeline ─────────────────────────────────────────────────────────

    # ── Handles features ──────────────────────────────────────────────────────

    def extract_handle_features(self) -> dict:
        """
        Run the Handles plugin to count open handles per process and break them
        down by type (Port, File, Event, Desktop, Key, Thread, Directory,
        Semaphore, Timer, Section, Mutant).
        """
        from volatility3.plugins.windows import handles

        rows = self._run_plugin(handles.Handles)

        type_counts: dict[str, int] = {}
        per_proc_counts: dict[int, int] = {}

        for row in rows:
            htype = str(row.get("Type") or "").strip()
            pid   = row.get("PID")
            if pid is not None:
                per_proc_counts[pid] = per_proc_counts.get(pid, 0) + 1
            if htype:
                type_counts[htype] = type_counts.get(htype, 0) + 1

        total   = sum(per_proc_counts.values())
        nprocs  = len(per_proc_counts)
        avg_per = total / nprocs if nprocs else 0.0

        return {
            "total_handles":     total,
            "avg_handles_per_proc": avg_per,
            "nport":      type_counts.get("Port",      0),
            "nfile":      type_counts.get("File",      0),
            "nevent":     type_counts.get("Event",     0),
            "ndesktop":   type_counts.get("Desktop",   0),
            "nkey":       type_counts.get("Key",       0),
            "nthread":    type_counts.get("Thread",    0),
            "ndirectory": type_counts.get("Directory", 0),
            "nsemaphore": type_counts.get("Semaphore", 0),
            "ntimer":     type_counts.get("Timer",     0),
            "nsection":   type_counts.get("Section",   0),
            "nmutant":    type_counts.get("Mutant",    0),
        }

    # ── Service scan features ─────────────────────────────────────────────────

    def extract_service_features(self) -> dict:
        """
        Run the SvcScan plugin to enumerate Windows services and classify them
        by service type (kernel driver, FS driver, process, shared-process,
        interactive-process).
        """
        from volatility3.plugins.windows import svcscan

        rows = self._run_plugin(svcscan.SvcScan)

        total      = 0
        kernel_drv = 0
        fs_drv     = 0
        proc_svc   = 0
        shared_svc = 0
        inter_svc  = 0
        active     = 0

        for row in rows:
            total += 1
            stype  = str(row.get("Type")  or "").lower()
            state  = str(row.get("State") or "").lower()

            if "kernel" in stype and "driver" in stype:
                kernel_drv += 1
            elif "file" in stype and "system" in stype:
                fs_drv += 1
            elif "interactive" in stype and "process" in stype:
                inter_svc += 1
            elif "share" in stype and "process" in stype:
                shared_svc += 1
            elif "own" in stype and "process" in stype:
                proc_svc += 1

            if "running" in state:
                active += 1

        return {
            "nservices":                   total,
            "kernel_drivers":              kernel_drv,
            "fs_drivers":                  fs_drv,
            "process_services":            proc_svc,
            "shared_process_services":     shared_svc,
            "interactive_process_services": inter_svc,
            "nactive":                     active,
        }

    # ── Fast pipeline (no Malfind / SvcScan) ─────────────────────────────────

    def extract_fast(self) -> dict:
        """
        Run only the fast plugins (PsList, PsScan, DllList, VadInfo, Handles).
        Skips Malfind and SvcScan — completes in seconds on any dump size.

        Returns the same dict structure as extract_all() so it can be fed
        straight into map_to_feature_vector().  The behavioral_indicators and
        service_features sections are zero-filled placeholders.
        """
        logger.info("Starting fast extraction (no Malfind/SvcScan): %s", self._dump_path)

        proc = self.extract_process_features()
        dlls = self.extract_dll_features()
        mem  = self.extract_memory_region_features()
        hdl  = self.extract_handle_features()

        behav = {
            "malfind_count": 0, "high_entropy_regions": 0,
            "injection_score": 0.0, "injection_evidence": [],
        }
        svc = {
            "nservices": 0, "kernel_drivers": 0, "fs_drivers": 0,
            "process_services": 0, "shared_process_services": 0,
            "interactive_process_services": 0, "nactive": 0,
        }

        summary = {
            "process_count":    proc["total_count"],
            "hidden_processes": proc["hidden_count"],
            "dll_count":        dlls["total_loaded"],
            "suspicious_dlls":  dlls["suspicious_paths_count"],
            "rwx_regions":      mem["rwx_count"],
            "malfind_hits":     0,
            "nservices":        0,
            "total_handles":    hdl["total_handles"],
            "risk_score":       _risk_score(
                hidden          = proc["hidden_count"],
                malfind_hits    = 0,
                rwx_regions     = mem["rwx_count"],
                suspicious_dlls = dlls["suspicious_paths_count"],
            ),
        }

        logger.info(
            "Fast extraction complete — processes: %d (hidden: %d), DLLs: %d, "
            "RWX: %d, handles: %d",
            summary["process_count"], summary["hidden_processes"],
            summary["dll_count"], summary["rwx_regions"], summary["total_handles"],
        )

        return {
            "dump_path":              self._dump_path,
            "extraction_timestamp":   datetime.now(timezone.utc).isoformat(),
            "process_features":       proc,
            "dll_features":           dlls,
            "memory_region_features": mem,
            "behavioral_indicators":  behav,
            "handle_features":        hdl,
            "service_features":       svc,
            "summary":                summary,
            "errors":                 self.errors,
        }

    # ── Full pipeline ─────────────────────────────────────────────────────────

    def extract_all(self) -> dict:
        """
        Run all extraction passes and return the complete feature dictionary.

        The returned dict is directly serialisable with json.dumps (all values
        are str, int, float, bool, list, dict, or None) and safe to INSERT
        into a PostgreSQL JSONB column.
        """
        logger.info("Starting feature extraction: %s", self._dump_path)

        proc   = self.extract_process_features()
        dlls   = self.extract_dll_features()
        mem    = self.extract_memory_region_features()
        behav  = self.extract_behavioral_indicators()
        hdl    = self.extract_handle_features()
        svc    = self.extract_service_features()

        summary = {
            "process_count":    proc["total_count"],
            "hidden_processes": proc["hidden_count"],
            "dll_count":        dlls["total_loaded"],
            "suspicious_dlls":  dlls["suspicious_paths_count"],
            "rwx_regions":      mem["rwx_count"],
            "malfind_hits":     behav["malfind_count"],
            "nservices":        svc["nservices"],
            "total_handles":    hdl["total_handles"],
            "risk_score":       _risk_score(
                hidden        = proc["hidden_count"],
                malfind_hits  = behav["malfind_count"],
                rwx_regions   = mem["rwx_count"],
                suspicious_dlls = dlls["suspicious_paths_count"],
            ),
        }

        logger.info(
            "Extraction complete — processes: %d (hidden: %d), "
            "DLLs: %d, RWX regions: %d, malfind hits: %d, "
            "handles: %d, services: %d, risk: %.2f",
            summary["process_count"], summary["hidden_processes"],
            summary["dll_count"], summary["rwx_regions"],
            summary["malfind_hits"], summary["total_handles"],
            summary["nservices"], summary["risk_score"],
        )

        return {
            "dump_path":               self._dump_path,
            "extraction_timestamp":    datetime.now(timezone.utc).isoformat(),
            "process_features":        proc,
            "dll_features":            dlls,
            "memory_region_features":  mem,
            "behavioral_indicators":   behav,
            "handle_features":         hdl,
            "service_features":        svc,
            "summary":                 summary,
            "errors":                  self.errors,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(dump_path: str) -> dict:
    """Full extraction: all seven plugins including Malfind and SvcScan."""
    return FeatureExtractor(dump_path).extract_all()


def extract_fast_features(dump_path: str) -> dict:
    """
    Fast extraction: PsList, PsScan, DllList, VadInfo, Handles only.
    Skips Malfind and SvcScan.  Completes in seconds regardless of dump size.
    Used as Stage 1 of the two-phase pipeline — the classifier makes a
    preliminary Benign/Malware call on these features before deciding whether
    the slow plugins are needed.
    """
    return FeatureExtractor(dump_path).extract_fast()
