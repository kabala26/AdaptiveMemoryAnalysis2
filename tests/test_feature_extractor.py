"""
Tests for modules/feature_extractor.py

Strategy
--------
Helper functions (_entropy, _safe, etc.) are tested against real Volatility 3
types — the library is installed so no mocking is needed there.

FeatureExtractor requires a valid file path and calls Volatility internally,
so all class-level tests:
  1. Create a throwaway temp file to satisfy the FileNotFoundError guard.
  2. Patch FeatureExtractor._setup() to a no-op so no real vol3 context is built.
  3. Patch FeatureExtractor._run_plugin() per-test to return controlled rows,
     letting us exercise each extraction method in isolation.
"""

import math
import os
import sys
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock

# Make sure the project root is on sys.path regardless of where pytest is run.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.feature_extractor import (
    _entropy,
    _has_pe_header,
    _is_suspicious_dll_path,
    _risk_score,
    _safe,
    _HIGH_ENTROPY_THRESHOLD,
    FeatureExtractor,
    extract_features,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def extractor(tmp_path):
    """FeatureExtractor instance with _setup patched out (no real vol3 context)."""
    dump = tmp_path / "test.raw"
    dump.write_bytes(b"\x00" * 4096)
    with patch.object(FeatureExtractor, "_setup"):
        fe = FeatureExtractor(str(dump))
    fe.errors = []
    return fe


# ─────────────────────────────────────────────────────────────────────────────
# _entropy
# ─────────────────────────────────────────────────────────────────────────────

class TestEntropy:
    def test_empty_returns_zero(self):
        assert _entropy(b"") == 0.0

    def test_single_byte_repeated_returns_zero(self):
        assert _entropy(b"\x00" * 1000) == 0.0

    def test_two_equal_symbols_returns_one(self):
        # Equal counts of 0x00 and 0xFF → H = 1.0
        data = b"\x00\xff" * 500
        assert abs(_entropy(data) - 1.0) < 0.001

    def test_uniform_256_symbols_near_eight(self):
        # All 256 byte values equally → H ≈ 8.0
        data = bytes(range(256)) * 4
        assert abs(_entropy(data) - 8.0) < 0.01

    def test_high_entropy_random_like(self):
        # Pseudo-random-looking data should score above threshold.
        data = bytes((i * 37 + 13) % 256 for i in range(4096))
        assert _entropy(data) >= _HIGH_ENTROPY_THRESHOLD

    def test_return_type_is_float(self):
        assert isinstance(_entropy(b"hello"), float)

    def test_result_rounded_to_four_places(self):
        val = _entropy(bytes(range(256)))
        assert val == round(val, 4)


# ─────────────────────────────────────────────────────────────────────────────
# _has_pe_header
# ─────────────────────────────────────────────────────────────────────────────

class TestHasPeHeader:
    def test_mz_signature_detected(self):
        assert _has_pe_header(b"MZ\x90\x00" + b"\x00" * 60) is True

    def test_non_mz_returns_false(self):
        assert _has_pe_header(b"\x7fELF\x00" + b"\x00" * 60) is False

    def test_empty_bytes_returns_false(self):
        assert _has_pe_header(b"") is False

    def test_single_byte_returns_false(self):
        assert _has_pe_header(b"M") is False

    def test_exactly_two_bytes_mz(self):
        assert _has_pe_header(b"MZ") is True

    def test_null_bytes_returns_false(self):
        assert _has_pe_header(b"\x00\x00\x00\x00") is False


# ─────────────────────────────────────────────────────────────────────────────
# _is_suspicious_dll_path
# ─────────────────────────────────────────────────────────────────────────────

class TestIsSuspiciousDllPath:
    def test_none_is_suspicious(self):
        assert _is_suspicious_dll_path(None) is True

    def test_empty_string_is_suspicious(self):
        assert _is_suspicious_dll_path("") is True

    def test_windows_system32_is_trusted(self):
        assert _is_suspicious_dll_path("C:\\Windows\\System32\\ntdll.dll") is False

    def test_windows_syswow64_is_trusted(self):
        assert _is_suspicious_dll_path("C:\\Windows\\SysWOW64\\kernel32.dll") is False

    def test_program_files_is_trusted(self):
        assert _is_suspicious_dll_path("C:\\Program Files\\App\\lib.dll") is False

    def test_program_files_x86_is_trusted(self):
        assert _is_suspicious_dll_path("C:\\Program Files (x86)\\App\\lib.dll") is False

    def test_temp_dir_is_suspicious(self):
        assert _is_suspicious_dll_path("C:\\Temp\\malware.dll") is True

    def test_appdata_temp_is_suspicious(self):
        assert _is_suspicious_dll_path(
            "C:\\Users\\user\\AppData\\Local\\Temp\\evil.dll"
        ) is True

    def test_users_public_is_suspicious(self):
        assert _is_suspicious_dll_path("C:\\Users\\Public\\inject.dll") is True

    def test_downloads_is_suspicious(self):
        assert _is_suspicious_dll_path("C:\\Users\\user\\Downloads\\loader.dll") is True

    def test_desktop_is_suspicious(self):
        assert _is_suspicious_dll_path("C:\\Users\\user\\Desktop\\payload.dll") is True

    def test_recycle_bin_is_suspicious(self):
        assert _is_suspicious_dll_path("C:\\$Recycle.Bin\\loader.dll") is True

    def test_case_insensitive(self):
        assert _is_suspicious_dll_path("C:\\TEMP\\EVIL.DLL") is True
        assert _is_suspicious_dll_path("C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL") is False


# ─────────────────────────────────────────────────────────────────────────────
# _risk_score
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskScore:
    def test_all_zero_inputs_returns_zero(self):
        assert _risk_score(0, 0, 0, 0) == 0.0

    def test_result_never_exceeds_one(self):
        assert _risk_score(100, 100, 100, 100) <= 1.0

    def test_result_never_below_zero(self):
        assert _risk_score(0, 0, 0, 0) >= 0.0

    def test_hidden_processes_increase_score(self):
        assert _risk_score(2, 0, 0, 0) > _risk_score(0, 0, 0, 0)

    def test_malfind_hits_increase_score(self):
        assert _risk_score(0, 3, 0, 0) > _risk_score(0, 0, 0, 0)

    def test_rwx_below_threshold_does_not_increase_score(self):
        # Fewer than 4 RWX regions: no contribution (threshold is > 3).
        assert _risk_score(0, 0, 3, 0) == _risk_score(0, 0, 0, 0)

    def test_rwx_above_threshold_increases_score(self):
        assert _risk_score(0, 0, 10, 0) > _risk_score(0, 0, 0, 0)

    def test_suspicious_dlls_increase_score(self):
        assert _risk_score(0, 0, 0, 3) > _risk_score(0, 0, 0, 0)

    def test_result_is_rounded_float(self):
        val = _risk_score(1, 2, 5, 1)
        assert isinstance(val, float)
        assert val == round(val, 4)

    def test_hidden_processes_capped(self):
        # Many hidden processes should not push score above 1.
        score_small = _risk_score(3, 0, 0, 0)
        score_large = _risk_score(30, 0, 0, 0)
        assert score_large == score_small  # cap applied at 3 hidden procs


# ─────────────────────────────────────────────────────────────────────────────
# _safe  (uses real vol3 types)
# ─────────────────────────────────────────────────────────────────────────────

class TestSafeConverter:
    def test_none_passthrough(self):
        assert _safe(None) is None

    def test_int_passthrough(self):
        assert _safe(42) == 42

    def test_str_passthrough(self):
        assert _safe("hello") == "hello"

    def test_bool_passthrough(self):
        assert _safe(True) is True

    # ── absent-value subclasses ───────────────────────────────────────────────

    def test_not_applicable_value_returns_none(self):
        from volatility3.framework.renderers import NotApplicableValue
        assert _safe(NotApplicableValue()) is None

    def test_not_available_value_returns_none(self):
        from volatility3.framework.renderers import NotAvailableValue
        assert _safe(NotAvailableValue()) is None

    def test_unreadable_value_returns_none(self):
        from volatility3.framework.renderers import UnreadableValue
        assert _safe(UnreadableValue()) is None

    def test_unparsable_value_returns_none(self):
        from volatility3.framework.renderers import UnparsableValue
        assert _safe(UnparsableValue()) is None

    # ── format hints ─────────────────────────────────────────────────────────

    def test_hex_converts_to_hex_string(self):
        from volatility3.framework.renderers.format_hints import Hex
        assert _safe(Hex(0x1000)) == "0x1000"

    def test_hex_zero(self):
        from volatility3.framework.renderers.format_hints import Hex
        assert _safe(Hex(0)) == "0x0"

    def test_hexbytes_returns_bytes(self):
        from volatility3.framework.renderers.format_hints import HexBytes
        raw = b"\xde\xad\xbe\xef"
        result = _safe(HexBytes(raw))
        assert isinstance(result, bytes)
        assert result == raw

    # ── datetime ─────────────────────────────────────────────────────────────

    def test_datetime_to_iso_string(self):
        dt = datetime(2026, 5, 11, 14, 30, 0)
        result = _safe(dt)
        assert result == "2026-05-11T14:30:00"
        assert isinstance(result, str)

    # ── Disassembly ──────────────────────────────────────────────────────────

    def test_disassembly_converts_to_string(self):
        from volatility3.framework.renderers import Disassembly
        disasm = Disassembly(b"\x90\x90", 0, "intel64")
        result = _safe(disasm)
        assert isinstance(result, str)

    # ── LayerData ────────────────────────────────────────────────────────────

    def test_layer_data_reads_bytes(self):
        from volatility3.framework.renderers import LayerData

        expected = b"\xca\xfe\xba\xbe" * 4
        mock_layer = MagicMock()
        mock_layer.read.return_value = expected
        mock_ctx = MagicMock()
        mock_ctx.layers = {"test_layer": mock_layer}

        ld = LayerData(
            context=mock_ctx,
            layer_name="test_layer",
            offset=0x1000,
            length=len(expected),
        )
        result = _safe(ld)
        assert result == expected
        mock_layer.read.assert_called_once_with(0x1000, len(expected), True)

    def test_layer_data_returns_none_on_read_error(self):
        from volatility3.framework.renderers import LayerData

        mock_layer = MagicMock()
        mock_layer.read.side_effect = OSError("paged out")
        mock_ctx = MagicMock()
        mock_ctx.layers = {"test_layer": mock_layer}

        ld = LayerData(context=mock_ctx, layer_name="test_layer", offset=0, length=16)
        assert _safe(ld) is None


# ─────────────────────────────────────────────────────────────────────────────
# FeatureExtractor — init and file validation
# ─────────────────────────────────────────────────────────────────────────────

class TestFeatureExtractorInit:
    def test_raises_file_not_found_for_missing_dump(self):
        with pytest.raises(FileNotFoundError, match="Memory dump not found"):
            FeatureExtractor("/nonexistent/path/dump.raw")

    def test_raises_runtime_error_when_vol3_missing(self, tmp_path):
        dump = tmp_path / "dump.raw"
        dump.write_bytes(b"\x00" * 16)
        import builtins, importlib
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name.startswith("volatility3"):
                raise ImportError("no module")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(RuntimeError, match="volatility3 is not installed"):
                FeatureExtractor(str(dump))

    def test_dump_path_is_absolute(self, tmp_path):
        dump = tmp_path / "dump.raw"
        dump.write_bytes(b"\x00" * 16)
        with patch.object(FeatureExtractor, "_setup"):
            fe = FeatureExtractor(str(dump))
        assert os.path.isabs(fe._dump_path)


# ─────────────────────────────────────────────────────────────────────────────
# FeatureExtractor — extract_process_features
# ─────────────────────────────────────────────────────────────────────────────

_PSLIST_ROWS = [
    {"PID": 4,    "PPID": 0,    "ImageFileName": "System",      "Threads": 147, "Handles": 2000,
     "SessionId": None, "Wow64": False, "CreateTime": "2026-01-01T00:00:00", "ExitTime": None},
    {"PID": 1234, "PPID": 4,    "ImageFileName": "svchost.exe", "Threads": 12,  "Handles": 300,
     "SessionId": 0,    "Wow64": False, "CreateTime": "2026-01-01T01:00:00", "ExitTime": None},
    {"PID": 5678, "PPID": 1234, "ImageFileName": "notepad.exe", "Threads": 3,   "Handles": 80,
     "SessionId": 1,    "Wow64": False, "CreateTime": "2026-01-01T02:00:00", "ExitTime": None},
]

_PSSCAN_ROWS_CLEAN = _PSLIST_ROWS.copy()

_PSSCAN_ROWS_WITH_HIDDEN = _PSLIST_ROWS + [
    {"PID": 9999, "PPID": 4, "ImageFileName": "malware.exe", "Threads": 2, "Handles": 10,
     "SessionId": 0, "Wow64": False, "CreateTime": "2026-01-01T03:00:00", "ExitTime": None},
]


class TestExtractProcessFeatures:
    def test_total_count_matches_pslist(self, extractor):
        with patch.object(extractor, "_run_plugin",
                          side_effect=[_PSLIST_ROWS, _PSSCAN_ROWS_CLEAN]):
            result = extractor.extract_process_features()
        assert result["total_count"] == 3

    def test_no_hidden_processes_when_lists_match(self, extractor):
        with patch.object(extractor, "_run_plugin",
                          side_effect=[_PSLIST_ROWS, _PSSCAN_ROWS_CLEAN]):
            result = extractor.extract_process_features()
        assert result["hidden_count"] == 0

    def test_detects_hidden_process(self, extractor):
        with patch.object(extractor, "_run_plugin",
                          side_effect=[_PSLIST_ROWS, _PSSCAN_ROWS_WITH_HIDDEN]):
            result = extractor.extract_process_features()
        assert result["hidden_count"] == 1
        assert result["total_count"] == 4

    def test_hidden_process_has_is_hidden_flag(self, extractor):
        with patch.object(extractor, "_run_plugin",
                          side_effect=[_PSLIST_ROWS, _PSSCAN_ROWS_WITH_HIDDEN]):
            result = extractor.extract_process_features()
        hidden = [p for p in result["processes"] if p["is_hidden"]]
        assert len(hidden) == 1
        assert hidden[0]["name"] == "malware.exe"
        assert hidden[0]["pid"] == 9999

    def test_listed_processes_have_is_hidden_false(self, extractor):
        with patch.object(extractor, "_run_plugin",
                          side_effect=[_PSLIST_ROWS, _PSSCAN_ROWS_CLEAN]):
            result = extractor.extract_process_features()
        assert all(not p["is_hidden"] for p in result["processes"])

    def test_parent_child_map_built_correctly(self, extractor):
        with patch.object(extractor, "_run_plugin",
                          side_effect=[_PSLIST_ROWS, _PSSCAN_ROWS_CLEAN]):
            result = extractor.extract_process_features()
        pcmap = result["parent_child_map"]
        # PID 1234 and 5678's parent is 4; PID 5678's parent is 1234
        assert "4" in pcmap["0"]      # System is child of 0
        assert "1234" in pcmap["4"]
        assert "5678" in pcmap["1234"]

    def test_returns_dict_with_required_keys(self, extractor):
        with patch.object(extractor, "_run_plugin",
                          side_effect=[_PSLIST_ROWS, _PSSCAN_ROWS_CLEAN]):
            result = extractor.extract_process_features()
        assert {"total_count", "hidden_count", "processes", "parent_child_map"} <= result.keys()

    def test_process_entry_has_required_fields(self, extractor):
        with patch.object(extractor, "_run_plugin",
                          side_effect=[_PSLIST_ROWS, _PSSCAN_ROWS_CLEAN]):
            result = extractor.extract_process_features()
        required = {"pid", "ppid", "name", "threads", "handles", "is_hidden",
                    "create_time", "exit_time"}
        for proc in result["processes"]:
            assert required <= proc.keys()

    def test_empty_pslist_produces_zero_counts(self, extractor):
        with patch.object(extractor, "_run_plugin", side_effect=[[], []]):
            result = extractor.extract_process_features()
        assert result["total_count"] == 0
        assert result["hidden_count"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# FeatureExtractor — extract_dll_features
# ─────────────────────────────────────────────────────────────────────────────

_DLLLIST_ROWS = [
    {"PID": 1234, "Process": "svchost.exe", "Base": "0x7fff0000", "Size": "0x1000",
     "Name": "ntdll.dll",  "Path": "C:\\Windows\\System32\\ntdll.dll",
     "LoadCount": 1, "LoadTime": "2026-01-01T00:00:00"},
    {"PID": 1234, "Process": "svchost.exe", "Base": "0x1234000",  "Size": "0x2000",
     "Name": "evil.dll",   "Path": "C:\\Temp\\evil.dll",
     "LoadCount": 1, "LoadTime": "2026-01-01T01:00:00"},
    {"PID": 5678, "Process": "notepad.exe", "Base": "0x5000",     "Size": "0x500",
     "Name": "inject.dll", "Path": None,
     "LoadCount": 1, "LoadTime": None},
]


class TestExtractDllFeatures:
    def test_total_loaded_count(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_DLLLIST_ROWS):
            result = extractor.extract_dll_features()
        assert result["total_loaded"] == 3

    def test_suspicious_paths_counted(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_DLLLIST_ROWS):
            result = extractor.extract_dll_features()
        assert result["suspicious_paths_count"] == 2   # Temp\\ + None path

    def test_trusted_dll_not_flagged(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_DLLLIST_ROWS):
            result = extractor.extract_dll_features()
        ntdll = next(d for d in result["dlls"] if d["dll_name"] == "ntdll.dll")
        assert ntdll["is_suspicious"] is False

    def test_temp_dll_flagged(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_DLLLIST_ROWS):
            result = extractor.extract_dll_features()
        evil = next(d for d in result["dlls"] if d["dll_name"] == "evil.dll")
        assert evil["is_suspicious"] is True

    def test_no_path_dll_flagged(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_DLLLIST_ROWS):
            result = extractor.extract_dll_features()
        injected = next(d for d in result["dlls"] if d["dll_name"] == "inject.dll")
        assert injected["is_suspicious"] is True

    def test_suspicious_dll_names_populated(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_DLLLIST_ROWS):
            result = extractor.extract_dll_features()
        assert "evil.dll" in result["suspicious_dll_names"]
        assert "inject.dll" in result["suspicious_dll_names"]
        assert "ntdll.dll" not in result["suspicious_dll_names"]

    def test_returns_required_keys(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_DLLLIST_ROWS):
            result = extractor.extract_dll_features()
        assert {"total_loaded", "suspicious_paths_count", "dlls", "suspicious_dll_names"} <= result.keys()

    def test_dll_entry_has_required_fields(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_DLLLIST_ROWS):
            result = extractor.extract_dll_features()
        required = {"pid", "process_name", "dll_name", "dll_path", "base_address",
                    "size", "is_suspicious"}
        for dll in result["dlls"]:
            assert required <= dll.keys()

    def test_empty_rows_returns_zero_counts(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=[]):
            result = extractor.extract_dll_features()
        assert result["total_loaded"] == 0
        assert result["suspicious_paths_count"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# FeatureExtractor — extract_memory_region_features
# ─────────────────────────────────────────────────────────────────────────────

_VADINFO_ROWS = [
    {"PID": 1234, "Process": "svchost.exe", "Start VPN": "0x1000", "End VPN": "0x2000",
     "Tag": "Vad ", "Protection": "PAGE_READONLY", "CommitCharge": 1,
     "PrivateMemory": 0, "Parent": "0x0", "Offset": "0x0", "File": None},
    {"PID": 1234, "Process": "svchost.exe", "Start VPN": "0x3000", "End VPN": "0x4000",
     "Tag": "VadS", "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 1,
     "PrivateMemory": 1, "Parent": "0x0", "Offset": "0x0", "File": None},
    {"PID": 5678, "Process": "notepad.exe", "Start VPN": "0x5000", "End VPN": "0x6000",
     "Tag": "VadS", "Protection": "PAGE_EXECUTE_WRITECOPY", "CommitCharge": 2,
     "PrivateMemory": 1, "Parent": "0x0", "Offset": "0x0", "File": None},
    # Large private+exec region > 1 MiB (0x300000 - 0x100000 + 1 = 2 MiB + 1)
    {"PID": 5678, "Process": "notepad.exe", "Start VPN": "0x100000", "End VPN": "0x300000",
     "Tag": "VadS", "Protection": "PAGE_EXECUTE_READ", "CommitCharge": 512,
     "PrivateMemory": 1, "Parent": "0x0", "Offset": "0x0", "File": None},
]


class TestExtractMemoryRegionFeatures:
    def test_total_region_count(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_VADINFO_ROWS):
            result = extractor.extract_memory_region_features()
        assert result["total_regions"] == 4

    def test_rwx_count(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_VADINFO_ROWS):
            result = extractor.extract_memory_region_features()
        # PAGE_EXECUTE_READWRITE and PAGE_EXECUTE_WRITECOPY count as RWX
        assert result["rwx_count"] == 2

    def test_read_only_region_not_rwx(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_VADINFO_ROWS):
            result = extractor.extract_memory_region_features()
        readonly = next(r for r in result["regions"] if r["protection"] == "PAGE_READONLY")
        assert readonly["is_rwx"] is False

    def test_execute_readwrite_is_rwx(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_VADINFO_ROWS):
            result = extractor.extract_memory_region_features()
        rwx = [r for r in result["regions"] if r["is_rwx"]]
        protections = {r["protection"] for r in rwx}
        assert "PAGE_EXECUTE_READWRITE" in protections
        assert "PAGE_EXECUTE_WRITECOPY" in protections

    def test_large_private_exec_region_flagged_suspicious(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_VADINFO_ROWS):
            result = extractor.extract_memory_region_features()
        large = next(
            r for r in result["regions"]
            if r["protection"] == "PAGE_EXECUTE_READ" and r["size_bytes"] is not None
            and r["size_bytes"] > 1_048_576
        )
        assert large["is_suspicious"] is True

    def test_region_size_computed_from_addresses(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_VADINFO_ROWS):
            result = extractor.extract_memory_region_features()
        first = result["regions"][0]
        # 0x2000 - 0x1000 + 1 = 0x1001 = 4097
        assert first["size_bytes"] == 0x1001

    def test_returns_required_keys(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_VADINFO_ROWS):
            result = extractor.extract_memory_region_features()
        assert {"total_regions", "rwx_count", "suspicious_allocations", "regions"} <= result.keys()

    def test_region_entry_has_required_fields(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_VADINFO_ROWS):
            result = extractor.extract_memory_region_features()
        required = {"pid", "process_name", "start_address", "end_address",
                    "size_bytes", "protection", "is_rwx", "is_suspicious"}
        for region in result["regions"]:
            assert required <= region.keys()

    def test_empty_rows_returns_zero_counts(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=[]):
            result = extractor.extract_memory_region_features()
        assert result["total_regions"] == 0
        assert result["rwx_count"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# FeatureExtractor — extract_behavioral_indicators
# ─────────────────────────────────────────────────────────────────────────────

_PE_BYTES   = b"MZ\x90\x00" + bytes(range(60))        # PE header present
_HIGH_ENT   = bytes((i * 251 + 7) % 256 for i in range(256))  # high entropy
_LOW_ENT    = b"\x00" * 256                             # zero entropy

_MALFIND_ROWS = [
    {"PID": 1234, "Process": "svchost.exe", "Start VPN": "0x3000", "End VPN": "0x4000",
     "Tag": "VadS", "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 1,
     "PrivateMemory": 1, "Notes": "Injected PE", "Hexdump": _PE_BYTES, "Disasm": "nop; nop"},
    {"PID": 5678, "Process": "notepad.exe", "Start VPN": "0x5000", "End VPN": "0x6000",
     "Tag": "VadS", "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 1,
     "PrivateMemory": 1, "Notes": "High entropy shellcode", "Hexdump": _HIGH_ENT, "Disasm": ""},
    {"PID": 9999, "Process": "clean.exe", "Start VPN": "0x7000", "End VPN": "0x8000",
     "Tag": "VadS", "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 1,
     "PrivateMemory": 0, "Notes": "", "Hexdump": _LOW_ENT, "Disasm": ""},
]


class TestExtractBehavioralIndicators:
    def test_malfind_count(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_MALFIND_ROWS):
            result = extractor.extract_behavioral_indicators()
        assert result["malfind_count"] == 3

    def test_pe_header_detected(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_MALFIND_ROWS):
            result = extractor.extract_behavioral_indicators()
        pe_hits = [e for e in result["injection_evidence"] if e["has_pe_header"]]
        assert len(pe_hits) == 1
        assert pe_hits[0]["process_name"] == "svchost.exe"

    def test_no_pe_header_for_non_mz(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_MALFIND_ROWS):
            result = extractor.extract_behavioral_indicators()
        no_pe = [e for e in result["injection_evidence"] if not e["has_pe_header"]]
        assert len(no_pe) == 2

    def test_high_entropy_counted(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_MALFIND_ROWS):
            result = extractor.extract_behavioral_indicators()
        assert result["high_entropy_regions"] >= 1

    def test_entropy_value_in_range(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_MALFIND_ROWS):
            result = extractor.extract_behavioral_indicators()
        for entry in result["injection_evidence"]:
            assert 0.0 <= entry["entropy"] <= 8.0

    def test_hex_preview_present_and_capped(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_MALFIND_ROWS):
            result = extractor.extract_behavioral_indicators()
        for entry in result["injection_evidence"]:
            if entry["hex_preview"] is not None:
                # 64 bytes → 128 hex chars
                assert len(entry["hex_preview"]) <= 128

    def test_empty_hexdump_handled_gracefully(self, extractor):
        rows = [{"PID": 1, "Process": "a.exe", "Start VPN": "0x1000", "End VPN": "0x2000",
                 "Tag": "VadS", "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 1,
                 "PrivateMemory": 1, "Notes": "", "Hexdump": None, "Disasm": ""}]
        with patch.object(extractor, "_run_plugin", return_value=rows):
            result = extractor.extract_behavioral_indicators()
        assert result["malfind_count"] == 1
        assert result["injection_evidence"][0]["entropy"] == 0.0
        assert result["injection_evidence"][0]["has_pe_header"] is False

    def test_injection_score_between_zero_and_one(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_MALFIND_ROWS):
            result = extractor.extract_behavioral_indicators()
        assert 0.0 <= result["injection_score"] <= 1.0

    def test_returns_required_keys(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_MALFIND_ROWS):
            result = extractor.extract_behavioral_indicators()
        assert {"malfind_count", "high_entropy_regions", "injection_score",
                "injection_evidence"} <= result.keys()

    def test_injection_entry_has_required_fields(self, extractor):
        with patch.object(extractor, "_run_plugin", return_value=_MALFIND_ROWS):
            result = extractor.extract_behavioral_indicators()
        required = {"pid", "process_name", "start_address", "end_address",
                    "protection", "entropy", "has_pe_header", "hex_preview"}
        for entry in result["injection_evidence"]:
            assert required <= entry.keys()


# ─────────────────────────────────────────────────────────────────────────────
# FeatureExtractor — extract_all (integration-level shape tests)
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractAll:
    def _make_side_effects(self):
        """Return plugin outputs in the order extract_all calls _run_plugin:
        pslist, psscan, dlllist, vadinfo, malfind."""
        return [
            _PSLIST_ROWS,
            _PSSCAN_ROWS_WITH_HIDDEN,
            _DLLLIST_ROWS,
            _VADINFO_ROWS,
            _MALFIND_ROWS,
        ]

    def test_top_level_keys_present(self, extractor):
        with patch.object(extractor, "_run_plugin", side_effect=self._make_side_effects()):
            result = extractor.extract_all()
        expected_keys = {
            "dump_path", "extraction_timestamp",
            "process_features", "dll_features",
            "memory_region_features", "behavioral_indicators",
            "summary", "errors",
        }
        assert expected_keys <= result.keys()

    def test_summary_keys_present(self, extractor):
        with patch.object(extractor, "_run_plugin", side_effect=self._make_side_effects()):
            result = extractor.extract_all()
        summary_keys = {
            "process_count", "hidden_processes", "dll_count",
            "suspicious_dlls", "rwx_regions", "malfind_hits", "risk_score",
        }
        assert summary_keys <= result["summary"].keys()

    def test_summary_risk_score_in_range(self, extractor):
        with patch.object(extractor, "_run_plugin", side_effect=self._make_side_effects()):
            result = extractor.extract_all()
        score = result["summary"]["risk_score"]
        assert 0.0 <= score <= 1.0

    def test_summary_counts_consistent_with_sub_dicts(self, extractor):
        with patch.object(extractor, "_run_plugin", side_effect=self._make_side_effects()):
            result = extractor.extract_all()
        s = result["summary"]
        assert s["process_count"]    == result["process_features"]["total_count"]
        assert s["hidden_processes"] == result["process_features"]["hidden_count"]
        assert s["dll_count"]        == result["dll_features"]["total_loaded"]
        assert s["rwx_regions"]      == result["memory_region_features"]["rwx_count"]
        assert s["malfind_hits"]     == result["behavioral_indicators"]["malfind_count"]

    def test_errors_list_present(self, extractor):
        with patch.object(extractor, "_run_plugin", side_effect=self._make_side_effects()):
            result = extractor.extract_all()
        assert isinstance(result["errors"], list)

    def test_extraction_timestamp_is_iso_string(self, extractor):
        with patch.object(extractor, "_run_plugin", side_effect=self._make_side_effects()):
            result = extractor.extract_all()
        ts = result["extraction_timestamp"]
        assert isinstance(ts, str)
        assert "T" in ts   # ISO 8601 separator

    def test_dump_path_in_output(self, extractor):
        with patch.object(extractor, "_run_plugin", side_effect=self._make_side_effects()):
            result = extractor.extract_all()
        assert result["dump_path"] == extractor._dump_path

    def test_result_is_json_serialisable(self, extractor):
        import json
        with patch.object(extractor, "_run_plugin", side_effect=self._make_side_effects()):
            result = extractor.extract_all()
        # Should not raise — every value must be a plain Python type.
        serialised = json.dumps(result)
        assert isinstance(serialised, str)


# ─────────────────────────────────────────────────────────────────────────────
# Error isolation
# ─────────────────────────────────────────────────────────────────────────────

class TestErrorIsolation:
    def test_failed_plugin_appends_to_errors(self, extractor):
        # Error isolation lives INSIDE _run_plugin (try/except around construct_plugin).
        # We must patch the vol3 call that _run_plugin wraps, not _run_plugin itself.
        extractor._ctx = MagicMock()
        extractor._automagics = []

        import volatility3.framework.plugins as fp
        with patch.object(fp, "construct_plugin",
                          side_effect=RuntimeError("layer stacking failed")):
            rows = extractor._run_plugin(MagicMock(__name__="FakePlugin"))

        assert rows == []
        assert len(extractor.errors) == 1
        assert "RuntimeError" in extractor.errors[0]

    def test_failed_plugin_returns_empty_data(self, extractor):
        """A failing plugin should produce empty lists, not crash the method."""
        with patch.object(extractor, "_run_plugin", return_value=[]):
            result = extractor.extract_process_features()
        assert result["total_count"] == 0
        assert result["processes"] == []

    def test_extract_all_accumulates_errors_list(self, extractor):
        call_count = 0

        def selective_fail(plugin_class):
            nonlocal call_count
            call_count += 1
            if call_count == 3:   # DllList fails
                extractor.errors.append(f"{plugin_class.__name__}: simulated")
                return []
            return []

        with patch.object(extractor, "_run_plugin", side_effect=selective_fail):
            result = extractor.extract_all()

        assert isinstance(result["errors"], list)


# ─────────────────────────────────────────────────────────────────────────────
# Module-level extract_features convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractFeaturesFunction:
    def test_raises_for_missing_file(self):
        with pytest.raises(FileNotFoundError):
            extract_features("/no/such/dump.raw")

    def test_delegates_to_extractor(self, tmp_path):
        dump = tmp_path / "dump.raw"
        dump.write_bytes(b"\x00" * 16)
        mock_result = {"summary": {}, "errors": []}

        with patch.object(FeatureExtractor, "_setup"), \
             patch.object(FeatureExtractor, "extract_all", return_value=mock_result):
            result = extract_features(str(dump))

        assert result is mock_result
