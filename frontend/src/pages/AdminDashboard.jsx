import { useState, useEffect, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { Users, ShieldAlert, Activity, HardDrive, Cpu, FileSearch, Loader2, AlertTriangle } from 'lucide-react'
import { useReactTable, getCoreRowModel, flexRender } from '@tanstack/react-table'
import Layout from '../components/Layout.jsx'
import api from '../utils/api.js'

function StatCard({ label, value, sub, icon: Icon, accent = 'text-amber-600 dark:text-amber-400', iconBg = 'bg-amber-100 dark:bg-amber-900/20' }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-6 shadow-sm">
      <div className="flex items-start justify-between mb-3">
        <div className={`w-10 h-10 rounded-xl ${iconBg} flex items-center justify-center`}>
          <Icon className={`w-5 h-5 ${accent}`} />
        </div>
      </div>
      <p className="text-[10px] font-mono text-gray-400 uppercase tracking-widest">{label}</p>
      <p className={`text-3xl font-bold font-mono mt-1 ${accent}`}>{value ?? '—'}</p>
      {sub && <p className="text-xs text-gray-400 mt-1">{sub}</p>}
    </div>
  )
}

const STATUS_COLORS = {
  complete:   'bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20',
  processing: 'bg-blue-500/10  text-blue-600  dark:text-blue-400  border-blue-500/20',
  pending:    'bg-gray-100     text-gray-500  dark:bg-gray-700    dark:text-gray-400',
  failed:     'bg-red-500/10   text-red-600   dark:text-red-400   border-red-500/20',
}

export default function AdminDashboard() {
  const [stats,   setStats]   = useState(null)
  const [dumps,   setDumps]   = useState([])
  const [loading, setLoading] = useState(true)
  const [filter,  setFilter]  = useState({ prediction: '', search: '' })

  useEffect(() => {
    Promise.all([
      api.get('/analysis/stats'),
      api.get('/analysis/dumps'),
    ]).then(([s, d]) => {
      setStats(s.data)
      setDumps(d.data.dumps || [])
    }).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const filtered = useMemo(() => {
    let rows = dumps
    if (filter.prediction) rows = rows.filter(d => d.prediction === filter.prediction)
    if (filter.search) {
      const q = filter.search.toLowerCase()
      rows = rows.filter(d => d.file_name?.toLowerCase().includes(q) || d.user_name?.toLowerCase().includes(q))
    }
    return rows
  }, [dumps, filter])

  const columns = useMemo(() => [
    { header: 'Filename',   accessorKey: 'file_name',   cell: i => <span className="text-sm font-medium text-gray-800 dark:text-gray-100">{i.getValue()}</span> },
    { header: 'User',       accessorKey: 'user_name',   cell: i => <span className="text-xs text-gray-500 dark:text-gray-400">{i.getValue() || '—'}</span> },
    { header: 'Date',       accessorKey: 'upload_date', cell: i => <span className="text-xs font-mono text-gray-500 dark:text-gray-400">{new Date(i.getValue()).toLocaleDateString()}</span> },
    { header: 'Status',     accessorKey: 'status',      cell: i => <span className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded-full border ${STATUS_COLORS[i.getValue()] || STATUS_COLORS.pending}`}>{i.getValue()}</span> },
    { header: 'Prediction', accessorKey: 'prediction',  cell: i => { const v = i.getValue(); return v ? <span className={`text-xs font-bold uppercase ${v === 'Malware' ? 'text-red-500' : 'text-green-500'}`}>{v}</span> : <span className="text-xs text-gray-400">—</span> } },
    { header: 'Confidence', accessorKey: 'confidence',  cell: i => { const v = i.getValue(); return v != null ? <span className="text-xs font-mono text-gray-600 dark:text-gray-400">{(v*100).toFixed(1)}%</span> : <span className="text-xs text-gray-400">—</span> } },
    { id: 'view', header: '', cell: i => <Link to={`/results/${i.row.original.dump_id}`} className="text-xs text-amber-600 dark:text-amber-400 hover:underline font-medium">View →</Link> },
  ], [])

  const table = useReactTable({ data: filtered, columns, getCoreRowModel: getCoreRowModel() })

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white tracking-tight">Admin Dashboard</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1 text-sm">System-wide forensic analysis overview</p>
        </div>

        {/* Stats */}
        {loading ? (
          <div className="flex items-center gap-3 text-gray-400"><Loader2 className="w-5 h-5 animate-spin" /> Loading stats…</div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <StatCard label="Total Analyses" value={stats?.total_analyses}   icon={FileSearch} />
            <StatCard label="Malware Today"  value={stats?.malware_today}    icon={AlertTriangle} accent="text-red-500" iconBg="bg-red-100 dark:bg-red-900/20" />
            <StatCard label="Detection Rate" value={stats ? `${(stats.detection_rate * 100).toFixed(1)}%` : '—'} icon={Activity} />
            <StatCard label="Disk Usage"     value={stats ? `${stats.disk_usage_mb} MB` : '—'} icon={HardDrive} />
            <StatCard label="Model Accuracy" value={stats?.last_model_accuracy ? `${(stats.last_model_accuracy * 100).toFixed(1)}%` : '—'} icon={Cpu} />
            <StatCard label="Last Trained"   value={stats?.last_model_date ? new Date(stats.last_model_date).toLocaleDateString() : 'Never'} icon={Users} sub="Model training date" />
          </div>
        )}

        {/* Quick nav */}
        <div className="flex flex-wrap gap-2">
          {[
            { label: 'Manage Users',   href: '/admin/users'  },
            { label: 'Model Versions', href: '/admin/models' },
            { label: 'Config',         href: '/admin/config' },
            { label: 'Audit Logs',     href: '/admin/logs'   },
          ].map(l => (
            <Link key={l.href} to={l.href} className="px-4 py-2 text-xs font-medium rounded-lg border border-amber-300 dark:border-amber-700 text-amber-700 dark:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-900/20 transition-colors">
              {l.label}
            </Link>
          ))}
        </div>

        {/* Filter row */}
        <div className="flex flex-wrap gap-3">
          <input
            type="text"
            placeholder="Search by file or user…"
            value={filter.search}
            onChange={e => setFilter(f => ({ ...f, search: e.target.value }))}
            className="input-field max-w-xs text-sm"
          />
          <select
            value={filter.prediction}
            onChange={e => setFilter(f => ({ ...f, prediction: e.target.value }))}
            className="input-field max-w-[160px] text-sm"
          >
            <option value="">All predictions</option>
            <option value="Malware">Malware</option>
            <option value="Benign">Benign</option>
          </select>
        </div>

        {/* All analyses table */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
            <h2 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">All Analyses ({filtered.length})</h2>
          </div>
          {loading ? (
            <div className="py-12 text-center text-sm text-gray-400">Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="py-12 text-center text-sm text-gray-400">No results match the filter.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  {table.getHeaderGroups().map(hg => (
                    <tr key={hg.id} className="border-b border-gray-200 dark:border-gray-700">
                      {hg.headers.map(h => (
                        <th key={h.id} className="px-5 py-3 text-[10px] font-bold text-gray-400 uppercase tracking-widest whitespace-nowrap">
                          {flexRender(h.column.columnDef.header, h.getContext())}
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                  {table.getRowModel().rows.map(row => (
                    <tr key={row.id} className="hover:bg-amber-50/30 dark:hover:bg-amber-900/10 transition-colors">
                      {row.getVisibleCells().map(cell => (
                        <td key={cell.id} className="px-5 py-3.5">
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </Layout>
  )
}
