"""
Maps FeatureExtractor.extract_all() output to the 55-column CICMalMem-2022
feature vector consumed by the trained Random Forest.

Features derivable from the current four Volatility plugins (PsList, PsScan,
DllList, VadInfo, Malfind) are computed here.  Features that require
additional plugins (Handles, Svcscan, Callbacks, Modules, LdrModules,
PsXview cross-checks) default to 0.0 — marked PARTIAL below.

To close those gaps, add the corresponding plugin in feature_extractor.py
and fill the PARTIAL slots in _build() below.
"""

import numpy as np

# Canonical column order from Obfuscated-MalMem2022.csv
FEATURE_NAMES = [
    # pslist (5)
    'pslist.nproc', 'pslist.nppid', 'pslist.avg_threads',
    'pslist.nprocs64bit', 'pslist.avg_handlers',
    # dlllist (2)
    'dlllist.ndlls', 'dlllist.avg_dlls_per_proc',
    # handles (13) — PARTIAL: only totals from pslist; per-type counts need handles plugin
    'handles.nhandles', 'handles.avg_handles_per_proc',
    'handles.nport', 'handles.nfile', 'handles.nevent',
    'handles.ndesktop', 'handles.nkey', 'handles.nthread',
    'handles.ndirectory', 'handles.nsemaphore', 'handles.ntimer',
    'handles.nsection', 'handles.nmutant',
    # ldrmodules (6) — PARTIAL: approximated from DLL path analysis
    'ldrmodules.not_in_load', 'ldrmodules.not_in_init',
    'ldrmodules.not_in_mem',
    'ldrmodules.not_in_load_avg', 'ldrmodules.not_in_init_avg',
    'ldrmodules.not_in_mem_avg',
    # malfind (4) — fully computed
    'malfind.ninjections', 'malfind.commitCharge',
    'malfind.protection', 'malfind.uniqueInjections',
    # psxview (14) — PARTIAL: only DKOM-hidden count from PsList vs PsScan
    'psxview.not_in_pslist', 'psxview.not_in_eprocess_pool',
    'psxview.not_in_ethread_pool', 'psxview.not_in_pspcid_list',
    'psxview.not_in_csrss_handles', 'psxview.not_in_session',
    'psxview.not_in_deskthrd',
    'psxview.not_in_pslist_false_avg',
    'psxview.not_in_eprocess_pool_false_avg',
    'psxview.not_in_ethread_pool_false_avg',
    'psxview.not_in_pspcid_list_false_avg',
    'psxview.not_in_csrss_handles_false_avg',
    'psxview.not_in_session_false_avg',
    'psxview.not_in_deskthrd_false_avg',
    # modules (1) — PARTIAL: requires modules plugin
    'modules.nmodules',
    # svcscan (7) — PARTIAL: requires svcscan plugin
    'svcscan.nservices', 'svcscan.kernel_drivers', 'svcscan.fs_drivers',
    'svcscan.process_services', 'svcscan.shared_process_services',
    'svcscan.interactive_process_services', 'svcscan.nactive',
    # callbacks (3) — PARTIAL: requires callbacks plugin
    'callbacks.ncallbacks', 'callbacks.nanonymous', 'callbacks.ngeneric',
]

assert len(FEATURE_NAMES) == 55, "Feature list must have exactly 55 entries"


def _mean(values: list) -> float:
    valid = [v for v in values if v is not None]
    return sum(valid) / len(valid) if valid else 0.0


def map_to_feature_vector(extracted: dict) -> np.ndarray:
    """
    Convert FeatureExtractor.extract_all() output to a (1, 55) ndarray.

    Args:
        extracted: dict returned by FeatureExtractor.extract_all()

    Returns:
        np.ndarray of shape (1, 55), dtype float64
    """
    procs    = extracted.get('process_features', {}).get('processes', [])
    dlls     = extracted.get('dll_features', {})
    behav    = extracted.get('behavioral_indicators', {})
    summary  = extracted.get('summary', {})
    inj_hits = behav.get('injection_evidence', [])

    nproc = int(summary.get('process_count') or 0)
    ndlls = int(summary.get('dll_count') or 0)

    # ── pslist ────────────────────────────────────────────────────────────────
    pslist_nproc       = nproc
    pslist_nppid       = len({p['ppid'] for p in procs if p.get('ppid') is not None})
    pslist_avg_threads = _mean([p.get('threads') for p in procs])
    pslist_nprocs64bit = sum(1 for p in procs if p.get('wow64') is False)
    pslist_avg_handler = _mean([p.get('handles') for p in procs])

    # ── dlllist ───────────────────────────────────────────────────────────────
    avg_dlls_per_proc  = ndlls / max(nproc, 1)

    # ── handles (partial — per-type counts require the handles plugin) ────────
    total_handles      = sum(p.get('handles') or 0 for p in procs)
    avg_handles        = _mean([p.get('handles') for p in procs])

    # ── ldrmodules (approximated from DLL path analysis) ─────────────────────
    dll_list           = dlls.get('dlls', [])
    no_path_dlls       = sum(1 for d in dll_list if not d.get('dll_path'))
    suspicious_dlls    = int(dlls.get('suspicious_paths_count') or 0)
    ldr_avg_load       = no_path_dlls   / max(nproc, 1)
    ldr_avg_init       = no_path_dlls   / max(nproc, 1)
    ldr_avg_mem        = suspicious_dlls / max(nproc, 1)

    # ── malfind (fully computed) ──────────────────────────────────────────────
    malfind_n          = int(behav.get('malfind_count') or 0)
    malfind_charge     = sum(h.get('commit_charge') or 0 for h in inj_hits)
    malfind_protection = len({h.get('protection') for h in inj_hits if h.get('protection')})
    malfind_unique     = len({h.get('pid') for h in inj_hits if h.get('pid') is not None})

    # ── psxview (partial — DKOM count from PsList vs PsScan diff) ────────────
    hidden = int(summary.get('hidden_processes') or 0)

    vec = [
        # pslist
        pslist_nproc, pslist_nppid, pslist_avg_threads,
        pslist_nprocs64bit, pslist_avg_handler,
        # dlllist
        ndlls, avg_dlls_per_proc,
        # handles (partial)
        total_handles, avg_handles,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        # ldrmodules (approximated)
        no_path_dlls, no_path_dlls, suspicious_dlls,
        ldr_avg_load, ldr_avg_init, ldr_avg_mem,
        # malfind
        malfind_n, malfind_charge, malfind_protection, malfind_unique,
        # psxview (partial)
        hidden,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        # modules (partial)
        0.0,
        # svcscan (partial)
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        # callbacks (partial)
        0.0, 0.0, 0.0,
    ]

    assert len(vec) == 55, f"Vector length mismatch: {len(vec)}"
    return np.array(vec, dtype=np.float64).reshape(1, -1)
