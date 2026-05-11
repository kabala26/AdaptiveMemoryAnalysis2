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
        vf.import_files(vp, prefix="volatility3.plugins")

        self._ctx = contexts.Context()
        self._ctx.config["automagic.LayerStacker.single_location"] = (
            f"file://{self._dump_path}"
        )
        self._automagics = automagic.available(self._ctx)

    def _run_plugin(self, plugin_class) -> list[dict]:
        """
        Construct and run one plugin against the shared context.
        Returns a list of row dicts with normalised Python values.
        """
        from volatility3.framework import plugins as fp

        try:
            constructed = fp.construct_plugin(
                self._ctx, self._automagics, plugin_class,
                "plugins", None, None,
            )
            treegrid = constructed.run()
            col_names = [col.name for col in treegrid.columns]
            rows = []
            for _depth, row in treegrid.generator():
                row_dict = {name: _safe(val) for name, val in zip(col_names, row)}
                rows.append(row_dict)
            return rows
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

    def extract_all(self) -> dict:
        """
        Run all four extraction passes and return the complete feature dictionary.

        The returned dict is directly serialisable with json.dumps (all values
        are str, int, float, bool, list, dict, or None) and safe to INSERT
        into a PostgreSQL JSONB column.
        """
        logger.info("Starting feature extraction: %s", self._dump_path)

        proc   = self.extract_process_features()
        dlls   = self.extract_dll_features()
        mem    = self.extract_memory_region_features()
        behav  = self.extract_behavioral_indicators()

        summary = {
            "process_count":    proc["total_count"],
            "hidden_processes": proc["hidden_count"],
            "dll_count":        dlls["total_loaded"],
            "suspicious_dlls":  dlls["suspicious_paths_count"],
            "rwx_regions":      mem["rwx_count"],
            "malfind_hits":     behav["malfind_count"],
            "risk_score":       _risk_score(
                hidden        = proc["hidden_count"],
                malfind_hits  = behav["malfind_count"],
                rwx_regions   = mem["rwx_count"],
                suspicious_dlls = dlls["suspicious_paths_count"],
            ),
        }

        logger.info(
            "Extraction complete — processes: %d (hidden: %d), "
            "DLLs: %d, RWX regions: %d, malfind hits: %d, risk: %.2f",
            summary["process_count"], summary["hidden_processes"],
            summary["dll_count"], summary["rwx_regions"],
            summary["malfind_hits"], summary["risk_score"],
        )

        return {
            "dump_path":               self._dump_path,
            "extraction_timestamp":    datetime.now(timezone.utc).isoformat(),
            "process_features":        proc,
            "dll_features":            dlls,
            "memory_region_features":  mem,
            "behavioral_indicators":   behav,
            "summary":                 summary,
            "errors":                  self.errors,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(dump_path: str) -> dict:
    """
    One-call interface for the analysis pipeline.

    Args:
        dump_path: Absolute or relative path to a Windows memory dump
                   (.raw, .mem, .vmem, or any format Volatility 3 supports).

    Returns:
        Feature dictionary as described in FeatureExtractor.extract_all().

    Raises:
        FileNotFoundError: if dump_path does not exist.
        RuntimeError:      if volatility3 is not installed.
    """
    return FeatureExtractor(dump_path).extract_all()
