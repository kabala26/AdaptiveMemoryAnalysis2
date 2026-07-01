import { useState, useEffect, useMemo } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { FileUp, ShieldAlert, ShieldCheck, Files, AlertTriangle, X } from 'lucide-react'
import { useReactTable, getCoreRowModel, flexRender } from '@tanstack/react-table'
import Layout from '../components/Layout.jsx'
import api from '../utils/api.js'

function StatCard({ label, value, sub, accent }) {
  return (
    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-2xl p-6 shadow-sm">
      <p className="text-[10px] font-mono text-gray-400 uppercase tracking-widest">{label}</p>
      <p className={`text-3xl font-bold font-mono mt-2 ${accent}`}>{value}</p>
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

export default function AnalystDashboard() {
  const location = useLocation()
  const [dumps,   setDumps]   = useState([])
  const [loading, setLoading] = useState(true)
  const [denied,  setDenied]  = useState(location.state?.accessDenied || false)

  useEffect(() => {
    api.get('/analysis/dumps')
      .then(r => setDumps(r.data.dumps || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const stats = useMemo(() => {
    const total     = dumps.length
    const malicious = dumps.filter(d => d.prediction === 'Malware').length
    const benign    = dumps.filter(d => d.prediction === 'Benign').length
    return { total, malicious, benign }
  }, [dumps])

  const columns = useMemo(() => [
    {
      header: 'Filename',
      accessorKey: 'file_name',
      cell: info => <span className="text-sm font-medium text-gray-800 dark:text-gray-100">{info.getValue()}</span>,
    },
    {
      header: 'Submitted',
      accessorKey: 'upload_date',
      cell: info => <span className="text-xs text-gray-500 dark:text-gray-400 font-mono">{new Date(info.getValue()).toLocaleString()}</span>,
    },
    {
      header: 'Status',
      accessorKey: 'status',
      cell: info => {
        const v = info.getValue()
        return <span className={`px-2.5 py-0.5 text-[10px] font-bold uppercase rounded-full border ${STATUS_COLORS[v] || STATUS_COLORS.pending}`}>{v}</span>
      },
    },
    {
      header: 'Prediction',
      accessorKey: 'prediction',
      cell: info => {
        const v = info.getValue()
        if (!v) return <span className="text-xs text-gray-400">—</span>
        return <span className={`text-xs font-bold uppercase tracking-wide ${v === 'Malware' ? 'text-red-500' : 'text-green-500'}`}>{v}</span>
      },
    },
    {
      header: 'Confidence',
      accessorKey: 'confidence',
      cell: info => {
        const v = info.getValue()
        if (v == null) return <span className="text-xs text-gray-400">—</span>
        return <span className="text-xs font-mono text-gray-700 dark:text-gray-300">{(v * 100).toFixed(1)}%</span>
      },
    },
    {
      id: 'actions',
      header: '',
      cell: info => (
        <Link
          to={`/results/${info.row.original.dump_id}`}
          className="text-xs text-blue-600 dark:text-blue-400 hover:underline font-medium"
        >
          View →
        </Link>
      ),
    },
  ], [])

  const table = useReactTable({ data: dumps, columns, getCoreRowModel: getCoreRowModel() })

  return (
    <Layout>
      <div className="space-y-6">
        {/* Access denied banner */}
        {denied && (
          <div className="flex items-center justify-between gap-3 px-5 py-3.5 rounded-xl bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-400">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span className="text-sm">Access denied — that page requires admin privileges.</span>
            </div>
            <button onClick={() => setDenied(false)}><X className="w-4 h-4" /></button>
          </div>
        )}

        {/* Header */}
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white tracking-tight">My Dashboard</h1>
            <p className="text-gray-500 dark:text-gray-400 mt-1 text-sm">Your memory dump analyses</p>
          </div>
          <Link to="/upload" className="flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium transition-colors whitespace-nowrap">
            <FileUp className="w-4 h-4" /> Upload Dump
          </Link>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <StatCard label="Total Uploads"   value={stats.total}     accent="text-blue-600 dark:text-blue-400" />
          <StatCard label="Malicious Found" value={stats.malicious} accent="text-red-500" />
          <StatCard label="Benign"          value={stats.benign}    accent="text-green-500" />
        </div>

        {/* Analyses table */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50 flex items-center justify-between">
            <h2 className="text-[10px] font-bold text-gray-500 dark:text-gray-400 uppercase tracking-widest">Recent Analyses</h2>
            <Link to="/analyst/reports" className="text-[10px] font-bold text-blue-600 dark:text-blue-400 uppercase tracking-wider hover:underline">
              All Reports →
            </Link>
          </div>

          {loading ? (
            <div className="py-16 text-center text-sm text-gray-400">Loading…</div>
          ) : dumps.length === 0 ? (
            <div className="py-16 text-center">
              <Files className="w-10 h-10 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
              <p className="text-sm text-gray-400">No analyses yet. <Link to="/upload" className="text-blue-600 dark:text-blue-400 underline">Upload your first dump.</Link></p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  {table.getHeaderGroups().map(hg => (
                    <tr key={hg.id} className="border-b border-gray-200 dark:border-gray-700">
                      {hg.headers.map(h => (
                        <th key={h.id} className="px-5 py-3 text-[10px] font-bold text-gray-400 uppercase tracking-widest">
                          {flexRender(h.column.columnDef.header, h.getContext())}
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                  {table.getRowModel().rows.map(row => (
                    <tr key={row.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/40 transition-colors">
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
