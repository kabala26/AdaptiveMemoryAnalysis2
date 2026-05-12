"""
Tests for modules/feature_mapper.py

Verifies that map_to_feature_vector returns a correctly shaped, typed
ndarray and that specific values map from the extract_all() output as expected.
"""

import numpy as np
import pytest

from modules.feature_mapper import FEATURE_NAMES, map_to_feature_vector

# ── Minimal extract_all() output used across tests ────────────────────────────

_EXTRACTED = {
    "dump_path": "/tmp/test.raw",
    "extraction_timestamp": "2026-05-12T15:00:00",
    "process_features": {
        "total_count": 3,
        "hidden_count": 1,
        "processes": [
            {"pid": 4,    "ppid": 0,    "name": "System",      "threads": 147,
             "handles": 2000, "is_hidden": False, "wow64": False,
             "create_time": None, "exit_time": None},
            {"pid": 1234, "ppid": 4,    "name": "svchost.exe", "threads": 12,
             "handles": 300, "is_hidden": False, "wow64": False,
             "create_time": None, "exit_time": None},
            {"pid": 5678, "ppid": 1234, "name": "notepad.exe", "threads": 3,
             "handles": 80,  "is_hidden": False, "wow64": False,
             "create_time": None, "exit_time": None},
        ],
        "parent_child_map": {},
    },
    "dll_features": {
        "total_loaded": 3,
        "suspicious_paths_count": 1,
        "dlls": [
            {"pid": 1234, "process_name": "svchost.exe", "dll_name": "ntdll.dll",
             "dll_path": "C:\\Windows\\System32\\ntdll.dll",
             "base_address": "0x7fff0000", "size": "0x1000", "is_suspicious": False},
            {"pid": 1234, "process_name": "svchost.exe", "dll_name": "evil.dll",
             "dll_path": "C:\\Temp\\evil.dll",
             "base_address": "0x1234000", "size": "0x2000", "is_suspicious": True},
            {"pid": 5678, "process_name": "notepad.exe", "dll_name": "inject.dll",
             "dll_path": None, "base_address": "0x5000", "size": "0x500",
             "is_suspicious": True},
        ],
        "suspicious_dll_names": ["evil.dll", "inject.dll"],
    },
    "memory_region_features": {
        "total_regions": 2, "rwx_count": 1, "suspicious_allocations": 1, "regions": []
    },
    "behavioral_indicators": {
        "malfind_count": 2,
        "high_entropy_regions": 1,
        "injection_score": 0.5,
        "injection_evidence": [
            {"pid": 1234, "process_name": "svchost.exe",
             "start_address": "0x3000", "end_address": "0x4000",
             "protection": "PAGE_EXECUTE_READWRITE",
             "entropy": 7.5, "has_pe_header": True, "hex_preview": "deadbeef",
             "commit_charge": 5},
        ],
    },
    "summary": {
        "process_count": 3, "hidden_processes": 1,
        "dll_count": 3,     "suspicious_dlls": 2,
        "rwx_regions": 1,   "malfind_hits": 2,
        "risk_score": 0.6,
    },
    "errors": [],
}

_EMPTY_EXTRACTED = {
    "process_features": {"total_count": 0, "hidden_count": 0, "processes": []},
    "dll_features":     {"total_loaded": 0, "suspicious_paths_count": 0, "dlls": []},
    "behavioral_indicators": {
        "malfind_count": 0, "injection_evidence": []
    },
    "summary": {"process_count": 0, "hidden_processes": 0, "dll_count": 0},
}


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE_NAMES constant
# ══════════════════════════════════════════════════════════════════════════════

class TestFeatureNames:
    def test_exactly_55_names(self):
        assert len(FEATURE_NAMES) == 55

    def test_no_duplicates(self):
        assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))

    def test_all_strings(self):
        assert all(isinstance(n, str) for n in FEATURE_NAMES)


# ══════════════════════════════════════════════════════════════════════════════
# map_to_feature_vector — output shape and type
# ══════════════════════════════════════════════════════════════════════════════

class TestMapToFeatureVector:
    def test_returns_ndarray(self):
        vec = map_to_feature_vector(_EXTRACTED)
        assert isinstance(vec, np.ndarray)

    def test_shape_is_1_by_55(self):
        vec = map_to_feature_vector(_EXTRACTED)
        assert vec.shape == (1, 55)

    def test_dtype_is_float64(self):
        vec = map_to_feature_vector(_EXTRACTED)
        assert vec.dtype == np.float64

    def test_all_values_finite(self):
        vec = map_to_feature_vector(_EXTRACTED)
        assert np.all(np.isfinite(vec))

    def test_all_values_nonneg(self):
        vec = map_to_feature_vector(_EXTRACTED)
        assert np.all(vec >= 0.0)

    def test_empty_input_returns_zeros(self):
        vec = map_to_feature_vector(_EMPTY_EXTRACTED)
        assert np.all(vec == 0.0)

    def test_process_count_mapped(self):
        # pslist.nproc is the first feature
        vec = map_to_feature_vector(_EXTRACTED)
        idx = FEATURE_NAMES.index("pslist.nproc")
        assert vec[0, idx] == 3.0

    def test_dll_count_mapped(self):
        # dlllist.ndlls
        vec = map_to_feature_vector(_EXTRACTED)
        idx = FEATURE_NAMES.index("dlllist.ndlls")
        assert vec[0, idx] == 3.0

    def test_malfind_injections_mapped(self):
        # malfind.ninjections
        vec = map_to_feature_vector(_EXTRACTED)
        idx = FEATURE_NAMES.index("malfind.ninjections")
        assert vec[0, idx] == 2.0

    def test_hidden_process_mapped_to_psxview(self):
        # psxview.not_in_pslist
        vec = map_to_feature_vector(_EXTRACTED)
        idx = FEATURE_NAMES.index("psxview.not_in_pslist")
        assert vec[0, idx] == 1.0

    def test_avg_threads_computed(self):
        # pslist.avg_threads = (147 + 12 + 3) / 3 = 54.0
        vec = map_to_feature_vector(_EXTRACTED)
        idx = FEATURE_NAMES.index("pslist.avg_threads")
        assert abs(vec[0, idx] - 54.0) < 0.01

    def test_avg_dlls_per_proc_computed(self):
        # dlllist.avg_dlls_per_proc = 3 / 3 = 1.0
        vec = map_to_feature_vector(_EXTRACTED)
        idx = FEATURE_NAMES.index("dlllist.avg_dlls_per_proc")
        assert abs(vec[0, idx] - 1.0) < 0.01

    def test_output_is_1d_reshapable(self):
        vec = map_to_feature_vector(_EXTRACTED)
        flat = vec.reshape(-1)
        assert flat.shape == (55,)
