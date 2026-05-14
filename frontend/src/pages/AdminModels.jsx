import { useState, useEffect } from 'react'
import { Cpu, CheckCircle2, RefreshCw, Download, AlertTriangle, Loader2 } from 'lucide-react'
import Layout from '../components/Layout.jsx'
import api from '../utils/api.js'
import { useToast } from '../hooks/useToast.jsx'

function ConfirmDialog({ open, onConfirm, onCancel }) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-8 max-w-sm w-full mx-4 shadow-2xl">
        <div className="flex flex-col items-center text-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-amber-100 dark:bg-amber-900/30 flex items-center justify-center">
            <RefreshCw className="w-7 h-7 text-amber-600 dark:text-amber-400" />
          </div>
          <div>
            <h3 className="font-display text-xl text-gray-900 dark:text-white">Confirm Retraining</h3>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              This will train a new Random Forest model on the full CICMalMem-2022 dataset. Estimated time: <strong>2–5 minutes</strong>. The current model stays active until training completes.
            </p>
          </div>
          <div className="flex gap-3 w-full">
            <button onClick={onConfirm} className="flex-1 py-3 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-sm font-medium transition-colors">
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

function exportFeatureData(model) {
  if (!model.feature_importance?.length) return
  const header = 'feature,importance'
  const rows   = model.feature_importance.map(f => `${f.feature},${f.importance}`)
  const csv    = [header, ...rows].join('\n')
  const blob   = new Blob([csv], { type: 'text/csv' })
  const url    = URL.createObjectURL(blob)
  const a      = document.createElement('a')
  a.href       = url
  a.download   = `features-${model.model_id.slice(0, 8)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

export default function AdminModels() {
  const toast = useToast()
  const [models,      setModels]      = useState([])
  const [loading,     setLoading]     = useState(true)
  const [showConfirm, setShowConfirm] = useState(false)
  const [retraining,  setRetraining]  = useState(false)
  const [activating,  setActivating]  = useState(null)

  async function fetchModels() {
    api.get('/analysis/models')
      .then(r => setModels(r.data.models || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchModels() }, [])

  async function handleRetrain() {
    setShowConfirm(false)
    setRetraining(true)
    try {
      await api.post('/analysis/retrain')
      toast.info('Retraining started — this may take a few minutes.')
      setTimeout(fetchModels, 60_000)
    } catch (e) {
      toast.error(e.response?.data?.message || 'Failed to start retraining.')
    } finally {
      setRetraining(false)
    }
  }

  async function handleActivate(modelId) {
    setActivating(modelId)
    try {
      await api.post(`/analysis/models/${modelId}/activate`)
      await fetchModels()
      toast.success('Model activated successfully.')
    } catch (e) {
      toast.error(e.response?.data?.message || 'Failed to activate model.')
    } finally {
      setActivating(null)
    }
  }

  return (
    <Layout>
      <ConfirmDialog open={showConfirm} onConfirm={handleRetrain} onCancel={() => setShowConfirm(false)} />

      <div className="space-y-6 max-w-4xl">
        <div className="flex items-end justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white tracking-tight">Model Management</h1>
            <p className="text-gray-500 dark:text-gray-400 mt-1 text-sm">Trained model versions and performance</p>
          </div>
          <button
            onClick={() => setShowConfirm(true)}
            disabled={retraining}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-amber-600 hover:bg-amber-500 disabled:opacity-60 text-white text-sm font-medium transition-colors"
          >
            {retraining ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
            Retrain Model
          </button>
        </div>

        {/* Model list */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
            <h2 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Trained Models ({models.length})</h2>
          </div>

          {loading ? (
            <div className="py-16 flex items-center justify-center gap-3 text-gray-400">
              <Loader2 className="w-5 h-5 animate-spin" /> Loading models…
            </div>
          ) : models.length === 0 ? (
            <div className="py-16 text-center">
              <Cpu className="w-10 h-10 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
              <p className="text-sm text-gray-400">No trained models yet. Click <strong>Retrain Model</strong> to start.</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-100 dark:divide-gray-700">
              {models.map(m => (
                <div key={m.model_id} className={`px-6 py-5 ${m.is_active ? 'bg-amber-50/40 dark:bg-amber-900/5' : 'hover:bg-gray-50 dark:hover:bg-gray-700/30'} transition-colors`}>
                  <div className="flex items-start gap-4">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${m.is_active ? 'bg-amber-500' : 'bg-gray-200 dark:bg-gray-700'}`}>
                      <Cpu className={`w-5 h-5 ${m.is_active ? 'text-white' : 'text-gray-400'}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-sm font-semibold text-gray-900 dark:text-white">{m.model_name}</p>
                        {m.is_active && (
                          <span className="flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 uppercase">
                            <CheckCircle2 className="w-3 h-3" /> Active
                          </span>
                        )}
                      </div>
                      <div className="mt-1 flex flex-wrap gap-4 text-xs text-gray-400 font-mono">
                        <span>Algorithm: {m.algorithm}</span>
                        <span>Accuracy: <span className="text-green-600 dark:text-green-400 font-bold">{m.accuracy ? (m.accuracy * 100).toFixed(2) + '%' : '—'}</span></span>
                        <span>Trained: {m.training_date ? new Date(m.training_date).toLocaleDateString() : '—'}</span>
                        {m.activated_at && <span>Activated: {new Date(m.activated_at).toLocaleDateString()}</span>}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {m.feature_importance?.length > 0 && (
                        <button
                          onClick={() => exportFeatureData(m)}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                        >
                          <Download className="w-3.5 h-3.5" /> Export CSV
                        </button>
                      )}
                      {!m.is_active && (
                        <button
                          onClick={() => handleActivate(m.model_id)}
                          disabled={activating === m.model_id}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-600 hover:bg-amber-500 disabled:opacity-60 text-white transition-colors"
                        >
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
        </div>
      </div>
    </Layout>
  )
}
