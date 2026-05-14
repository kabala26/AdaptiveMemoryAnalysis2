import { useState, useEffect, useCallback } from 'react'
import { Tag, ChevronLeft, ChevronRight, Loader2, Plus, RefreshCw, CheckCircle2, Clock } from 'lucide-react'
import Layout from '../components/Layout.jsx'
import api from '../utils/api.js'
import { useToast } from '../hooks/useToast.jsx'

const LABEL_COLORS = {
  Malware: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  Benign:  'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
}

const SOURCE_COLORS = {
  manual:                'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
  confirmed_prediction:  'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
}

function AddSampleForm({ onAdded }) {
  const toast = useToast()
  const [open,       setOpen]       = useState(false)
  const [dumpId,     setDumpId]     = useState('')
  const [trueLabel,  setTrueLabel]  = useState('Malware')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setSubmitting(true)
    try {
      await api.post('/analysis/labeled-samples', {
        dump_id:    dumpId.trim() || undefined,
        true_label: trueLabel,
      })
      toast.success('Labeled sample saved.')
      setDumpId('')
      setOpen(false)
      onAdded()
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to save labeled sample.')
    } finally {
      setSubmitting(false)
    }
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-sm font-medium transition-colors"
      >
        <Plus className="w-4 h-4" /> Add Label
      </button>
    )
  }

  return (
    <form onSubmit={handleSubmit} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-2xl p-6 shadow-sm flex flex-wrap gap-4 items-end">
      <div className="flex-1 min-w-[200px]">
        <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1.5">
          Dump ID <span className="text-gray-400">(optional — leave blank for manual vector)</span>
        </label>
        <input
          type="text"
          placeholder="UUID of an analysed dump…"
          value={dumpId}
          onChange={e => setDumpId(e.target.value)}
          className="input-field w-full text-sm font-mono"
        />
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1.5">True Label</label>
        <select
          value={trueLabel}
          onChange={e => setTrueLabel(e.target.value)}
          className="input-field text-sm"
        >
          <option value="Malware">Malware</option>
          <option value="Benign">Benign</option>
        </select>
      </div>
      <div className="flex gap-2">
        <button
          type="submit"
          disabled={submitting}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-amber-600 hover:bg-amber-500 disabled:opacity-60 text-white text-sm font-medium transition-colors"
        >
          {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
          Save
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="px-4 py-2.5 rounded-xl border border-gray-300 dark:border-gray-600 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
        >
          Cancel
        </button>
      </div>
    </form>
  )
}

export default function AdminLabeledSamples() {
  const [samples, setSamples]   = useState([])
  const [total,   setTotal]     = useState(0)
  const [pending, setPending]   = useState(0)
  const [page,    setPage]      = useState(1)
  const [loading, setLoading]   = useState(true)
  const PER_PAGE = 50

  const fetchSamples = useCallback(() => {
    setLoading(true)
    api.get(`/analysis/labeled-samples?page=${page}&per_page=${PER_PAGE}`)
      .then(r => {
        setSamples(r.data.samples || [])
        setTotal(r.data.total   || 0)
        setPending(r.data.pending || 0)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [page])

  useEffect(() => { fetchSamples() }, [fetchSamples])

  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))
  const malwareCount = samples.filter(s => s.true_label === 'Malware').length
  const benignCount  = samples.filter(s => s.true_label === 'Benign').length

  return (
    <Layout>
      <div className="space-y-6 max-w-5xl">
        <div className="flex items-end justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white tracking-tight">Labeled Samples</h1>
            <p className="text-gray-500 dark:text-gray-400 mt-1 text-sm">Ground-truth labels used for adaptive retraining</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={fetchSamples}
              className="flex items-center gap-2 px-4 py-2 rounded-xl border border-gray-300 dark:border-gray-600 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            >
              <RefreshCw className="w-4 h-4" /> Refresh
            </button>
          </div>
        </div>

        {/* Stat tiles */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Total Samples', value: total,    icon: Tag },
            { label: 'Pending',       value: pending,  icon: Clock,        accent: 'text-amber-600 dark:text-amber-400', bg: 'bg-amber-100 dark:bg-amber-900/20' },
            { label: 'Malware',       value: malwareCount, icon: Tag,      accent: 'text-red-500',   bg: 'bg-red-100 dark:bg-red-900/20' },
            { label: 'Benign',        value: benignCount,  icon: CheckCircle2, accent: 'text-green-600 dark:text-green-400', bg: 'bg-green-100 dark:bg-green-900/20' },
          ].map(({ label, value, icon: Icon, accent = 'text-amber-600 dark:text-amber-400', bg = 'bg-amber-100 dark:bg-amber-900/20' }) => (
            <div key={label} className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-5 shadow-sm">
              <div className={`w-8 h-8 rounded-xl ${bg} flex items-center justify-center mb-3`}>
                <Icon className={`w-4 h-4 ${accent}`} />
              </div>
              <p className="text-[10px] text-gray-400 uppercase tracking-widest">{label}</p>
              <p className={`text-2xl font-bold font-mono mt-1 ${accent}`}>{loading ? '—' : value}</p>
            </div>
          ))}
        </div>

        {/* Pending notice */}
        {!loading && pending > 0 && (
          <div className="flex items-center gap-3 p-4 rounded-xl bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700 text-sm text-amber-700 dark:text-amber-400">
            <Clock className="w-4 h-4 flex-shrink-0" />
            <span>
              <strong>{pending}</strong> sample{pending !== 1 ? 's' : ''} not yet included in any model.
              Trigger a retrain from <strong>Model Management</strong> to include them.
            </span>
          </div>
        )}

        {/* Add form */}
        <AddSampleForm onAdded={fetchSamples} />

        {/* Table */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50 flex items-center justify-between">
            <h2 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-2">
              <Tag className="w-3.5 h-3.5" /> {total} Labeled Samples
            </h2>
            <span className="text-xs text-gray-400 font-mono">Page {page} / {totalPages}</span>
          </div>

          {loading ? (
            <div className="py-16 flex items-center justify-center gap-3 text-gray-400">
              <Loader2 className="w-5 h-5 animate-spin" /> Loading…
            </div>
          ) : samples.length === 0 ? (
            <div className="py-16 text-center">
              <Tag className="w-10 h-10 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
              <p className="text-sm text-gray-400">No labeled samples yet. Click <strong>Add Label</strong> to add the first one.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    {['Added At', 'True Label', 'Source', 'Dump ID', 'Included In Model'].map(h => (
                      <th key={h} className="px-5 py-3 text-[10px] font-bold text-gray-400 uppercase tracking-widest whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                  {samples.map(s => (
                    <tr key={s.sample_id} className="hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors">
                      <td className="px-5 py-3.5">
                        <span className="text-xs font-mono text-gray-500 dark:text-gray-400 whitespace-nowrap">
                          {new Date(s.added_at).toLocaleString()}
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        <span className={`px-2.5 py-0.5 text-[10px] font-bold uppercase rounded-full ${LABEL_COLORS[s.true_label] || 'bg-gray-100 text-gray-500'}`}>
                          {s.true_label}
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        <span className={`px-2 py-0.5 text-[10px] font-mono rounded ${SOURCE_COLORS[s.source] || 'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400'}`}>
                          {s.source}
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        {s.dump_id
                          ? <a href={`/results/${s.dump_id}`} className="text-[10px] font-mono text-amber-600 dark:text-amber-400 hover:underline truncate block max-w-[140px]">{s.dump_id}</a>
                          : <span className="text-xs text-gray-400">—</span>
                        }
                      </td>
                      <td className="px-5 py-3.5">
                        {s.included_in_model_id
                          ? <span className="flex items-center gap-1 text-[10px] font-mono text-green-600 dark:text-green-400"><CheckCircle2 className="w-3 h-3" />{s.included_in_model_id.slice(0, 8)}…</span>
                          : <span className="flex items-center gap-1 text-[10px] text-amber-600 dark:text-amber-400"><Clock className="w-3 h-3" />Pending</span>
                        }
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination */}
          <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <button
              disabled={page === 1}
              onClick={() => setPage(p => p - 1)}
              className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-400 disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            >
              <ChevronLeft className="w-3.5 h-3.5" /> Previous
            </button>
            <span className="text-xs text-gray-400 font-mono">{page} / {totalPages}</span>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage(p => p + 1)}
              className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-400 disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            >
              Next <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </Layout>
  )
}
