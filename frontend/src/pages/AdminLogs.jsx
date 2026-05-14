import { useState, useEffect, useCallback } from 'react'
import { ShieldAlert, ChevronLeft, ChevronRight, Loader2, Filter, Download } from 'lucide-react'
import Layout from '../components/Layout.jsx'
import api from '../utils/api.js'

const ACTION_COLORS = {
  upload:         'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
  analyze:        'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
  retrain:        'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
  activate_model: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
  delete_dump:    'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  label_sample:   'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-400',
  cleanup_uploads:'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
}

const ACTION_OPTIONS = [
  { value: '',               label: 'All actions' },
  { value: 'upload',         label: 'Upload' },
  { value: 'analyze',        label: 'Analyze' },
  { value: 'retrain',        label: 'Retrain' },
  { value: 'activate_model', label: 'Activate Model' },
  { value: 'delete_dump',    label: 'Delete Dump' },
  { value: 'label_sample',   label: 'Label Sample' },
  { value: 'cleanup_uploads','label': 'Cleanup' },
]

function exportLogsCSV(logs) {
  const header = 'timestamp,user,email,action,resource_type,resource_id,ip_address'
  const rows = logs.map(l => [
    l.timestamp,
    l.user_name  || '',
    l.user_email || '',
    l.action,
    l.resource_type || '',
    l.resource_id   || '',
    l.ip_address    || '',
  ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))
  const csv  = [header, ...rows].join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = `audit-logs-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

export default function AdminLogs() {
  const [logs,         setLogs]         = useState([])
  const [total,        setTotal]        = useState(0)
  const [page,         setPage]         = useState(1)
  const [loading,      setLoading]      = useState(true)
  const [actionFilter, setActionFilter] = useState('')
  const [search,       setSearch]       = useState('')
  const PER_PAGE = 50

  const fetchLogs = useCallback(() => {
    setLoading(true)
    const params = new URLSearchParams({ page, per_page: PER_PAGE })
    if (actionFilter) params.set('action', actionFilter)
    api.get(`/analysis/logs?${params}`)
      .then(r => { setLogs(r.data.logs || []); setTotal(r.data.total || 0) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [page, actionFilter])

  useEffect(() => { fetchLogs() }, [fetchLogs])

  // Reset to page 1 when filter changes
  useEffect(() => { setPage(1) }, [actionFilter])

  const filtered = search
    ? logs.filter(l =>
        l.user_name?.toLowerCase().includes(search.toLowerCase()) ||
        l.action?.includes(search.toLowerCase()) ||
        l.ip_address?.includes(search)
      )
    : logs

  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))

  return (
    <Layout>
      <div className="space-y-6 max-w-5xl">
        <div className="flex items-end justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white tracking-tight">Audit Logs</h1>
            <p className="text-gray-500 dark:text-gray-400 mt-1 text-sm">User activity and system events</p>
          </div>
          <button
            onClick={() => exportLogsCSV(filtered)}
            disabled={filtered.length === 0}
            className="flex items-center gap-2 px-4 py-2 rounded-xl border border-gray-300 dark:border-gray-600 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-40 transition-colors"
          >
            <Download className="w-4 h-4" /> Export CSV
          </button>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-3">
          <div className="relative">
            <Filter className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter by user or IP…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="input-field pl-9 max-w-xs text-sm"
            />
          </div>
          <select
            value={actionFilter}
            onChange={e => setActionFilter(e.target.value)}
            className="input-field max-w-[180px] text-sm"
          >
            {ACTION_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <button
            onClick={fetchLogs}
            className="px-4 py-2 rounded-xl border border-gray-300 dark:border-gray-600 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            Refresh
          </button>
        </div>

        {/* Table */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50 flex items-center justify-between">
            <h2 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-2">
              <ShieldAlert className="w-3.5 h-3.5" /> {total} Events
            </h2>
            <div className="flex items-center gap-2 text-xs text-gray-400">
              Page {page} of {totalPages}
            </div>
          </div>

          {loading ? (
            <div className="py-16 flex items-center justify-center gap-3 text-gray-400">
              <Loader2 className="w-5 h-5 animate-spin" /> Loading audit logs…
            </div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center text-sm text-gray-400">No audit events found.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    {['Timestamp', 'User', 'Action', 'Resource', 'IP Address', 'Details'].map(h => (
                      <th key={h} className="px-5 py-3 text-[10px] font-bold text-gray-400 uppercase tracking-widest whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                  {filtered.map(log => (
                    <tr key={log.log_id} className="hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors">
                      <td className="px-5 py-3.5">
                        <span className="text-xs font-mono text-gray-500 dark:text-gray-400 whitespace-nowrap">
                          {new Date(log.timestamp).toLocaleString()}
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        <div>
                          <p className="text-sm font-medium text-gray-800 dark:text-gray-200">{log.user_name || '—'}</p>
                          <p className="text-[10px] text-gray-400">{log.user_email || ''}</p>
                        </div>
                      </td>
                      <td className="px-5 py-3.5">
                        <span className={`px-2.5 py-0.5 text-[10px] font-bold uppercase rounded-full ${ACTION_COLORS[log.action] || 'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400'}`}>
                          {log.action}
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        <div>
                          {log.resource_type && <p className="text-xs text-gray-500 dark:text-gray-400">{log.resource_type}</p>}
                          {log.resource_id   && <p className="text-[10px] font-mono text-gray-400 truncate max-w-[120px]">{log.resource_id}</p>}
                        </div>
                      </td>
                      <td className="px-5 py-3.5">
                        <span className="text-xs font-mono text-gray-500 dark:text-gray-400">{log.ip_address || '—'}</span>
                      </td>
                      <td className="px-5 py-3.5">
                        {log.details && Object.keys(log.details).length > 0 ? (
                          <details className="text-[10px] text-gray-400 cursor-pointer">
                            <summary className="select-none hover:text-gray-600 dark:hover:text-gray-300">View</summary>
                            <pre className="mt-1 p-2 bg-gray-50 dark:bg-gray-900 rounded text-[9px] font-mono max-w-[200px] overflow-auto">
                              {JSON.stringify(log.details, null, 2)}
                            </pre>
                          </details>
                        ) : <span className="text-gray-300 dark:text-gray-600">—</span>}
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
