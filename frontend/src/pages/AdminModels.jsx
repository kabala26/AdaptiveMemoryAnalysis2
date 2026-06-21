import { useState, useEffect, useRef } from 'react'
import {
  Cpu, CheckCircle2, RefreshCw, Download, Loader2,
  Upload, Database, XCircle, ToggleLeft, ToggleRight,
  Trash2, ChevronDown, ChevronUp, AlertTriangle, Info,
} from 'lucide-react'
import Layout from '../components/Layout.jsx'
import api from '../utils/api.js'
import { useToast } from '../hooks/useToast.jsx'

// ── Helpers ───────────────────────────────────────────────────────────────────

function pct(v) { return v != null ? `${(v * 100).toFixed(2)}%` : '—' }

function StatusBadge({ status }) {
  const map = {
    pending_review: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
    approved:       'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
    rejected:       'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  }
  return (
    <span className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded-full ${map[status] || ''}`}>
      {status?.replace('_', ' ')}
    </span>
  )
}

function Section({ title, children }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm">
      <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
        <h2 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">{title}</h2>
      </div>
      {children}
    </div>
  )
}

// ── Retrain confirm dialog ────────────────────────────────────────────────────

function RetrainDialog({ open, activeCount, onConfirm, onCancel }) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-8 max-w-sm w-full mx-4 shadow-2xl">
        <div className="flex flex-col items-center text-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-navy-100 dark:bg-navy-800/40 flex items-center justify-center">
            <RefreshCw className="w-7 h-7 text-navy-700 dark:text-navy-300" />
          </div>
          <div>
            <h3 className="font-display text-xl text-gray-900 dark:text-white">Confirm Retraining</h3>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              Will train on <strong>CICMalMem-2022</strong>
              {activeCount > 0 && <> + <strong>{activeCount} additional dataset{activeCount > 1 ? 's' : ''}</strong></>}.
              The CICMEM test set is the neutral accuracy gate — if the new model does not improve, the current model stays active.
            </p>
          </div>
          <div className="flex gap-3 w-full">
            <button onClick={onConfirm} className="flex-1 py-3 rounded-xl bg-navy-700 hover:bg-navy-600 text-white text-sm font-medium transition-colors">
              Start Retraining
            </button>
            <button onClick={onCancel} className="flex-1 py-3 rounded-xl border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 text-sm hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Dataset comparison report accordion ──────────────────────────────────────

function ComparisonReport({ report }) {
  const [open, setOpen] = useState(false)
  if (!report) return null
  const fc = report.feature_comparison || {}
  const ov = report.overlap || {}
  return (
    <div className="mt-2">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1.5 text-[10px] font-bold text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 uppercase tracking-wide transition-colors"
      >
        {open ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        Comparison report
      </button>
      {open && (
        <div className="mt-2 bg-gray-50 dark:bg-gray-900/40 rounded-xl p-4 space-y-3 text-xs">
          {report.warnings?.length > 0 && (
            <div className="space-y-1">
              {report.warnings.map((w, i) => (
                <div key={i} className="flex items-start gap-1.5 text-amber-600 dark:text-amber-400">
                  <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" /> {w}
                </div>
              ))}
            </div>
          )}
          <div className="grid grid-cols-2 gap-2 font-mono text-gray-600 dark:text-gray-400">
            <span>Similarity score</span>
            <span className="font-bold text-gray-900 dark:text-white">{fc.similarity_score != null ? `${(fc.similarity_score * 100).toFixed(1)}%` : '—'}</span>
            <span>Features w/ drift</span>
            <span className="font-bold text-gray-900 dark:text-white">{fc.drifted_features ?? '—'} / {fc.total_features ?? '—'}</span>
            <span>Exact duplicates</span>
            <span className="font-bold text-gray-900 dark:text-white">{ov.exact_duplicates ?? '—'} ({ov.duplicate_pct ?? '—'}%)</span>
          </div>
          {fc.top_drifted?.length > 0 && (
            <div>
              <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wide mb-1">Top drifted features</p>
              <div className="space-y-0.5">
                {fc.top_drifted.slice(0, 5).map(f => (
                  <div key={f.feature} className="flex justify-between font-mono">
                    <span className="text-gray-600 dark:text-gray-400 truncate">{f.feature}</span>
                    <span className="text-red-500 ml-2">KS={f.ks_stat}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AdminModels() {
  const toast = useToast()
  const fileRef = useRef(null)

  const [tab,          setTab]          = useState('models')
  const [models,       setModels]       = useState([])
  const [datasets,     setDatasets]     = useState([])
  const [lastRetrain,  setLastRetrain]  = useState(null)
  const [loading,      setLoading]      = useState(true)
  const [showConfirm,  setShowConfirm]  = useState(false)
  const [retraining,   setRetraining]   = useState(false)
  const [activating,   setActivating]   = useState(null)
  const [uploading,    setUploading]    = useState(false)
  const [actionBusy,   setActionBusy]   = useState(null)

  const activeDatasets = datasets.filter(d => d.status === 'approved' && d.is_active)

  async function fetchAll() {
    try {
      const [mRes, dRes, lRes] = await Promise.all([
        api.get('/analysis/models'),
        api.get('/analysis/datasets'),
        api.get('/analysis/logs?per_page=50'),
      ])
      setModels(mRes.data.models || [])
      setDatasets(dRes.data.datasets || [])
      const retrainLog = (lRes.data.logs || []).find(l => l.action === 'retrain')
      setLastRetrain(retrainLog?.details || null)
    } catch (_) {}
    finally { setLoading(false) }
  }

  useEffect(() => { fetchAll() }, [])

  function exportFeatureData(model) {
    if (!model.feature_importance?.length) return
    const csv = ['feature,importance', ...model.feature_importance.map(f => `${f.feature},${f.importance}`)].join('\n')
    const a   = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(new Blob([csv], { type: 'text/csv' })),
      download: `features-${model.model_id.slice(0, 8)}.csv`,
    })
    a.click()
  }

  async function handleRetrain() {
    setShowConfirm(false)
    setRetraining(true)
    try {
      await api.post('/analysis/retrain')
      toast.info('Retraining started — this may take a few minutes.')
      setTimeout(fetchAll, 90_000)
    } catch (e) {
      toast.error(e.response?.data?.message || 'Failed to start retraining.')
    } finally { setRetraining(false) }
  }

  async function handleActivate(modelId) {
    setActivating(modelId)
    try {
      await api.post(`/analysis/models/${modelId}/activate`)
      await fetchAll()
      toast.success('Model activated.')
    } catch (e) {
      toast.error(e.response?.data?.message || 'Failed to activate.')
    } finally { setActivating(null) }
  }

  async function handleUpload(file) {
    if (!file) return
    setUploading(true)
    const fd = new FormData()
    fd.append('file', file)
    try {
      await api.post('/analysis/datasets/upload', fd)
      toast.success('Dataset uploaded and validated.')
      await fetchAll()
      setTab('datasets')
    } catch (e) {
      const msg = e.response?.data?.errors?.[0] || e.response?.data?.message || 'Upload failed.'
      toast.error(msg)
    } finally { setUploading(false) }
  }

  async function dsAction(id, action) {
    setActionBusy(id + action)
    try {
      await api.post(`/analysis/datasets/${id}/${action}`)
      await fetchAll()
    } catch (e) {
      toast.error(e.response?.data?.message || `Failed to ${action}.`)
    } finally { setActionBusy(null) }
  }

  async function handleDeleteDataset(id, name) {
    if (!confirm(`Delete dataset "${name}"? This cannot be undone.`)) return
    setActionBusy(id + 'delete')
    try {
      await api.delete(`/analysis/datasets/${id}`)
      toast.success('Dataset deleted.')
      await fetchAll()
    } catch (e) {
      toast.error(e.response?.data?.message || 'Failed to delete.')
    } finally { setActionBusy(null) }
  }

  return (
    <Layout>
      <RetrainDialog
        open={showConfirm}
        activeCount={activeDatasets.length}
        onConfirm={handleRetrain}
        onCancel={() => setShowConfirm(false)}
      />
      <input ref={fileRef} type="file" accept=".csv" className="hidden"
        onChange={e => { handleUpload(e.target.files?.[0]); e.target.value = '' }} />

      <div className="space-y-6 max-w-5xl">

        {/* Header */}
        <div className="flex items-end justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white tracking-tight">Training & Models</h1>
            <p className="text-gray-500 dark:text-gray-400 mt-1 text-sm">
              Model versions · Additional datasets · Retrain comparison
            </p>
          </div>
          <button
            onClick={() => setShowConfirm(true)}
            disabled={retraining}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-navy-700 hover:bg-navy-600 disabled:opacity-60 text-white text-sm font-medium transition-colors"
          >
            {retraining ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
            Retrain Model {activeDatasets.length > 0 && `(+${activeDatasets.length} dataset${activeDatasets.length > 1 ? 's' : ''})`}
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 bg-gray-100 dark:bg-gray-800 rounded-xl p-1 w-fit">
          {[['models', 'Models', Cpu], ['datasets', 'Datasets', Database]].map(([key, label, Icon]) => (
            <button
              key={key}
              onClick={() => setTab(key)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                tab === key
                  ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
              }`}
            >
              <Icon className="w-4 h-4" /> {label}
              {key === 'datasets' && datasets.filter(d => d.status === 'pending_review').length > 0 && (
                <span className="ml-1 w-4 h-4 rounded-full bg-amber-500 text-white text-[9px] font-bold flex items-center justify-center">
                  {datasets.filter(d => d.status === 'pending_review').length}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* ── MODELS TAB ── */}
        {tab === 'models' && (
          <div className="space-y-5">
            {/* Last retrain outcome */}
            {lastRetrain && (
              <div className={`rounded-2xl border-2 p-5 ${
                lastRetrain.activated
                  ? 'border-green-400 bg-green-50 dark:bg-green-900/10'
                  : 'border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-800'
              }`}>
                <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-2">Last Retrain Result</p>
                <div className="flex flex-wrap gap-6">
                  <div>
                    <p className="text-xs text-gray-400">Outcome</p>
                    <p className={`text-lg font-bold ${lastRetrain.activated ? 'text-green-600 dark:text-green-400' : 'text-gray-500'}`}>
                      {lastRetrain.activated ? '✓ Activated' : '— Kept previous (no improvement)'}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-400">CICMEM accuracy (neutral)</p>
                    <p className="text-lg font-bold font-mono text-gray-900 dark:text-white">
                      {lastRetrain.new_accuracy != null ? pct(lastRetrain.new_accuracy) : '—'}
                      {lastRetrain.prev_accuracy != null && (
                        <span className={`text-sm ml-2 ${lastRetrain.new_accuracy >= lastRetrain.prev_accuracy ? 'text-green-500' : 'text-red-500'}`}>
                          ({lastRetrain.new_accuracy >= lastRetrain.prev_accuracy ? '+' : ''}
                          {((lastRetrain.new_accuracy - lastRetrain.prev_accuracy) * 100).toFixed(3)}pp)
                        </span>
                      )}
                    </p>
                  </div>
                  {lastRetrain.additional_rows > 0 && (
                    <div>
                      <p className="text-xs text-gray-400">Additional rows used</p>
                      <p className="text-lg font-bold font-mono text-gray-900 dark:text-white">{lastRetrain.additional_rows?.toLocaleString()}</p>
                    </div>
                  )}
                </div>

                {/* Per-dataset breakdown */}
                {lastRetrain.per_dataset && Object.keys(lastRetrain.per_dataset).length > 0 && (
                  <div className="mt-4">
                    <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-2">Per-Dataset Evaluation (20% holdout)</p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {Object.values(lastRetrain.per_dataset).map(ds => (
                        <div key={ds.file_name} className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-3">
                          <p className="text-xs font-semibold text-gray-800 dark:text-gray-200 truncate">{ds.file_name}</p>
                          <div className="mt-1 flex gap-4 text-[10px] font-mono text-gray-400">
                            <span>Acc: <span className="text-gray-900 dark:text-white font-bold">{pct(ds.accuracy)}</span></span>
                            <span>F1: <span className="text-gray-900 dark:text-white font-bold">{pct(ds.f1_macro)}</span></span>
                            <span>{ds.n_samples?.toLocaleString()} samples</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Model list */}
            <Section title={`Trained Models (${models.length})`}>
              {loading ? (
                <div className="py-16 flex items-center justify-center gap-3 text-gray-400">
                  <Loader2 className="w-5 h-5 animate-spin" /> Loading…
                </div>
              ) : models.length === 0 ? (
                <div className="py-16 text-center">
                  <Cpu className="w-10 h-10 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
                  <p className="text-sm text-gray-400">No trained models yet. Click <strong>Retrain Model</strong> to start.</p>
                </div>
              ) : (
                <div className="divide-y divide-gray-100 dark:divide-gray-700">
                  {models.map(m => (
                    <div key={m.model_id} className={`px-4 sm:px-6 py-5 ${m.is_active ? 'bg-navy-50/40 dark:bg-navy-900/10' : 'hover:bg-gray-50 dark:hover:bg-gray-700/30'} transition-colors`}>
                      <div className="flex flex-wrap items-start gap-4">
                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${m.is_active ? 'bg-navy-700' : 'bg-gray-200 dark:bg-gray-700'}`}>
                          <Cpu className={`w-5 h-5 ${m.is_active ? 'text-white' : 'text-gray-400'}`} />
                        </div>
                        <div className="flex-1 min-w-[180px]">
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="text-sm font-semibold text-gray-900 dark:text-white">{m.model_name}</p>
                            {m.is_active && (
                              <span className="flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-navy-100 dark:bg-navy-800/50 text-navy-700 dark:text-navy-200 uppercase">
                                <CheckCircle2 className="w-3 h-3" /> Active
                              </span>
                            )}
                          </div>
                          <div className="mt-1 flex flex-wrap gap-4 text-xs text-gray-400 font-mono">
                            <span>Accuracy: <span className="text-green-600 dark:text-green-400 font-bold">{m.accuracy ? pct(m.accuracy) : '—'}</span></span>
                            <span>Trained: {m.training_date ? new Date(m.training_date).toLocaleDateString() : '—'}</span>
                            {m.activated_at && <span>Activated: {new Date(m.activated_at).toLocaleDateString()}</span>}
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-wrap w-full sm:w-auto sm:flex-shrink-0 pl-[56px] sm:pl-0">
                          {m.feature_importance?.length > 0 && (
                            <button onClick={() => exportFeatureData(m)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors">
                              <Download className="w-3.5 h-3.5" /> Export CSV
                            </button>
                          )}
                          {!m.is_active && (
                            <button onClick={() => handleActivate(m.model_id)} disabled={activating === m.model_id} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-navy-700 hover:bg-navy-600 disabled:opacity-60 text-white transition-colors">
                              {activating === m.model_id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                              Activate
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Section>
          </div>
        )}

        {/* ── DATASETS TAB ── */}
        {tab === 'datasets' && (
          <div className="space-y-5">
            {/* Upload zone */}
            <div
              onClick={() => !uploading && fileRef.current?.click()}
              className="rounded-2xl border-2 border-dashed border-gray-300 dark:border-gray-600 hover:border-navy-400 dark:hover:border-navy-500 bg-white dark:bg-gray-800 p-10 text-center cursor-pointer transition-colors"
            >
              {uploading ? (
                <div className="flex flex-col items-center gap-2 text-navy-700">
                  <Loader2 className="w-8 h-8 animate-spin" />
                  <p className="text-sm font-medium">Validating dataset…</p>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-3 text-gray-400">
                  <Upload className="w-10 h-10" />
                  <div>
                    <p className="font-medium text-gray-700 dark:text-gray-200">Upload additional dataset</p>
                    <p className="text-sm mt-1">CSV only · Must match CICMalMem-2022 schema (55 features + Class column)</p>
                  </div>
                </div>
              )}
            </div>

            {/* Info banner */}
            <div className="flex items-start gap-3 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-xl">
              <Info className="w-4 h-4 text-blue-500 mt-0.5 flex-shrink-0" />
              <p className="text-xs text-blue-700 dark:text-blue-300 leading-relaxed">
                Datasets are always kept separate from CICMalMem-2022.
                On retrain, each active dataset is split 80/20 — 80% goes into training, 20% is held out for per-dataset evaluation.
                The CICMEM test split is the neutral accuracy gate: the new model only replaces the current one if it scores higher on CICMEM.
              </p>
            </div>

            {/* Dataset list */}
            <Section title={`Additional Datasets (${datasets.length})`}>
              {datasets.length === 0 ? (
                <div className="py-16 text-center">
                  <Database className="w-10 h-10 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
                  <p className="text-sm text-gray-400">No datasets uploaded yet.</p>
                </div>
              ) : (
                <div className="divide-y divide-gray-100 dark:divide-gray-700">
                  {datasets.map(ds => {
                    const busy = key => actionBusy === ds.dataset_id + key
                    const cd   = ds.comparison_report?.class_distribution || {}
                    return (
                      <div key={ds.dataset_id} className="px-4 sm:px-6 py-5">
                        <div className="flex flex-wrap items-start gap-4">
                          <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${
                            ds.status === 'approved' ? 'bg-green-100 dark:bg-green-900/30' :
                            ds.status === 'rejected' ? 'bg-red-100 dark:bg-red-900/30' :
                            'bg-amber-100 dark:bg-amber-900/30'
                          }`}>
                            <Database className={`w-5 h-5 ${
                              ds.status === 'approved' ? 'text-green-600' :
                              ds.status === 'rejected' ? 'text-red-500' : 'text-amber-600'
                            }`} />
                          </div>

                          <div className="flex-1 min-w-[180px]">
                            <div className="flex items-center gap-2 flex-wrap">
                              <p className="text-sm font-semibold text-gray-900 dark:text-white truncate">{ds.file_name}</p>
                              <StatusBadge status={ds.status} />
                              {ds.is_active && (
                                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 uppercase">
                                  Active in retrain
                                </span>
                              )}
                            </div>
                            <div className="mt-1 flex flex-wrap gap-4 text-xs text-gray-400 font-mono">
                              <span>{ds.sample_count?.toLocaleString() ?? '—'} samples</span>
                              {cd.benign != null && <span>Benign: {cd.benign.toLocaleString()} ({cd.benign_pct}%)</span>}
                              {cd.malware != null && <span>Malware: {cd.malware.toLocaleString()} ({cd.malware_pct}%)</span>}
                              <span>Uploaded: {new Date(ds.uploaded_at).toLocaleDateString()}</span>
                            </div>
                            <ComparisonReport report={ds.comparison_report} />
                          </div>

                          {/* Actions */}
                          <div className="flex items-center gap-2 flex-wrap w-full sm:w-auto sm:flex-shrink-0 justify-end pl-[56px] sm:pl-0">
                            {ds.status === 'pending_review' && (
                              <>
                                <button
                                  onClick={() => dsAction(ds.dataset_id, 'approve')}
                                  disabled={busy('approve')}
                                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-green-600 hover:bg-green-500 disabled:opacity-60 text-white transition-colors"
                                >
                                  {busy('approve') ? <Loader2 className="w-3 h-3 animate-spin" /> : <CheckCircle2 className="w-3 h-3" />}
                                  Approve
                                </button>
                                <button
                                  onClick={() => dsAction(ds.dataset_id, 'reject')}
                                  disabled={busy('reject')}
                                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-600 hover:bg-red-500 disabled:opacity-60 text-white transition-colors"
                                >
                                  {busy('reject') ? <Loader2 className="w-3 h-3 animate-spin" /> : <XCircle className="w-3 h-3" />}
                                  Reject
                                </button>
                              </>
                            )}
                            {ds.status === 'approved' && (
                              <button
                                onClick={() => dsAction(ds.dataset_id, 'toggle')}
                                disabled={busy('toggle')}
                                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border ${
                                  ds.is_active
                                    ? 'border-blue-400 text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20'
                                    : 'border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700'
                                }`}
                              >
                                {busy('toggle') ? <Loader2 className="w-3 h-3 animate-spin" /> :
                                  ds.is_active ? <ToggleRight className="w-3.5 h-3.5" /> : <ToggleLeft className="w-3.5 h-3.5" />}
                                {ds.is_active ? 'Deactivate' : 'Activate'}
                              </button>
                            )}
                            <button
                              onClick={() => handleDeleteDataset(ds.dataset_id, ds.file_name)}
                              disabled={busy('delete')}
                              className="p-1.5 rounded-lg text-gray-300 dark:text-gray-600 hover:bg-red-50 dark:hover:bg-red-900/20 hover:text-red-500 transition-colors disabled:opacity-30"
                            >
                              {busy('delete') ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                            </button>
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </Section>
          </div>
        )}
      </div>
    </Layout>
  )
}
