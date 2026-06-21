import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { FileText, Download, AlertTriangle, CheckCircle2, Loader2 } from 'lucide-react'
import Layout from '../components/Layout.jsx'
import api from '../utils/api.js'
import { downloadReportPdf } from '../utils/reportPdf.js'
import { useToast } from '../hooks/useToast.jsx'

export default function AnalystReports() {
  const toast = useToast()
  const [dumps,       setDumps]       = useState([])
  const [loading,     setLoading]     = useState(true)
  const [downloading, setDownloading] = useState(null)

  useEffect(() => {
    api.get('/analysis/dumps')
      .then(r => setDumps((r.data.dumps || []).filter(d => d.status === 'complete')))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  async function handleDownload(dump) {
    setDownloading(dump.dump_id)
    try {
      await downloadReportPdf(dump, async (dumpId) => {
        const res = await api.get(`/analysis/results/${dumpId}`)
        return res.data
      })
    } catch (e) {
      toast.error('Failed to generate report.')
    } finally {
      setDownloading(null)
    }
  }

  return (
    <Layout>
      <div className="space-y-6 max-w-4xl">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white tracking-tight">My Reports</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1 text-sm">Completed forensic analysis reports</p>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
            <h2 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">
              {loading ? 'Loading…' : `${dumps.length} completed ${dumps.length === 1 ? 'analysis' : 'analyses'}`}
            </h2>
          </div>

          {loading ? (
            <div className="py-16 flex items-center justify-center gap-3 text-gray-400">
              <Loader2 className="w-5 h-5 animate-spin" /> Loading reports…
            </div>
          ) : dumps.length === 0 ? (
            <div className="py-16 text-center">
              <FileText className="w-10 h-10 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
              <p className="text-sm text-gray-400">No completed analyses yet.</p>
              <Link to="/upload" className="mt-3 inline-block text-sm text-blue-600 dark:text-blue-400 underline">Upload a memory dump</Link>
            </div>
          ) : (
            <ul className="divide-y divide-gray-100 dark:divide-gray-700">
              {dumps.map(dump => (
                <li key={dump.dump_id} className="flex items-center gap-4 px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700/40 transition-colors">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${
                    dump.prediction === 'Malware'
                      ? 'bg-red-100 dark:bg-red-900/20'
                      : 'bg-green-100 dark:bg-green-900/20'
                  }`}>
                    {dump.prediction === 'Malware'
                      ? <AlertTriangle className="w-5 h-5 text-red-500" />
                      : <CheckCircle2  className="w-5 h-5 text-green-500" />}
                  </div>

                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 dark:text-white truncate">{dump.file_name}</p>
                    <p className="text-xs text-gray-400 mt-0.5 font-mono">
                      {new Date(dump.upload_date).toLocaleDateString()} ·{' '}
                      <span className={dump.prediction === 'Malware' ? 'text-red-500' : 'text-green-500'}>
                        {dump.prediction}
                      </span>
                      {dump.confidence != null && <> · {(dump.confidence * 100).toFixed(1)}%</>}
                      {dump.malware_family && <> · <span className="text-amber-500">{dump.malware_family}</span></>}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0">
                    <Link
                      to={`/results/${dump.dump_id}`}
                      className="text-xs text-blue-600 dark:text-blue-400 hover:underline font-medium"
                    >
                      View
                    </Link>
                    <button
                      onClick={() => handleDownload(dump)}
                      disabled={downloading === dump.dump_id}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors disabled:opacity-50"
                    >
                      {downloading === dump.dump_id
                        ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        : <Download className="w-3.5 h-3.5" />}
                      PDF
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Layout>
  )
}
