import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { AlertTriangle, CheckCircle2, FileText, Calendar, HardDrive, Hash, Loader2 } from 'lucide-react'
import Layout from '../components/Layout.jsx'
import api from '../utils/api.js'

function ConfidenceGauge({ value }) {
  const pct = Math.round((value ?? 0) * 100)
  const color = pct >= 80 ? '#22c55e' : pct >= 60 ? '#f59e0b' : '#ef4444'
  const rotation = -90 + (pct / 100) * 180
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="120" height="68" viewBox="0 0 120 68">
        <path d="M10 60 A50 50 0 0 1 110 60" fill="none" stroke="#e5e7eb" strokeWidth="12" strokeLinecap="round" className="dark:[stroke:#374151]" />
        <path
          d="M10 60 A50 50 0 0 1 110 60"
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${(pct / 100) * 157} 157`}
        />
        <line x1="60" y1="60" x2="60" y2="18" stroke={color} strokeWidth="3" strokeLinecap="round"
          style={{ transformOrigin: '60px 60px', transform: `rotate(${rotation}deg)` }} />
        <circle cx="60" cy="60" r="4" fill={color} />
      </svg>
      <p className="text-3xl font-bold font-mono" style={{ color }}>{pct}%</p>
      <p className="text-xs text-gray-400">Confidence score</p>
    </div>
  )
}

function FeatureBar({ feature, importance, max }) {
  const pct = max > 0 ? (importance / max) * 100 : 0
  return (
    <div className="flex items-center gap-3 group">
      <span className="text-xs font-mono text-gray-500 dark:text-gray-400 w-40 flex-shrink-0 truncate" title={feature}>{feature}</span>
      <div className="flex-1 h-2 bg-gray-100 dark:bg-gray-700 rounded-full overflow-hidden">
        <div className="h-full bg-blue-500 rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-gray-400 w-14 text-right">{(importance * 100).toFixed(2)}%</span>
    </div>
  )
}

export default function ResultPage() {
  const { dump_id } = useParams()
  const [result, setResult]  = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  useEffect(() => {
    api.get(`/analysis/results/${dump_id}`)
      .then(r => setResult(r.data))
      .catch(() => setError('Could not load results. Check your access permissions.'))
      .finally(() => setLoading(false))
  }, [dump_id])

  if (loading) return (
    <Layout>
      <div className="flex items-center justify-center h-64 text-gray-400 gap-3">
        <Loader2 className="w-5 h-5 animate-spin" /> Loading results…
      </div>
    </Layout>
  )

  if (error) return (
    <Layout>
      <div className="max-w-lg mx-auto mt-20 text-center">
        <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <p className="text-gray-600 dark:text-gray-400">{error}</p>
        <Link to="/upload" className="mt-4 inline-block text-sm text-blue-600 dark:text-blue-400 underline">← Upload another</Link>
      </div>
    </Layout>
  )

  if (!result?.prediction && result?.status !== 'complete') return (
    <Layout>
      <div className="max-w-lg mx-auto mt-20 text-center">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin mx-auto mb-3" />
        <p className="text-gray-600 dark:text-gray-400">Analysis in progress — status: <span className="font-mono font-medium">{result?.status}</span></p>
      </div>
    </Layout>
  )

  const isMalicious = result.prediction === 'Malware'
  const top10 = (result.feature_importance || []).slice(0, 10)
  const maxImp = top10[0]?.importance || 1

  return (
    <Layout>
      <div className="max-w-3xl mx-auto space-y-5">
        {/* Verdict banner */}
        <div className={`rounded-2xl border-2 p-8 ${
          isMalicious
            ? 'border-red-400 bg-red-50 dark:bg-red-900/10'
            : 'border-green-400 bg-green-50 dark:bg-green-900/10'
        }`}>
          <div className="flex flex-wrap items-center justify-between gap-6">
            <div className="flex items-center gap-4">
              {isMalicious
                ? <AlertTriangle className="w-14 h-14 text-red-500 flex-shrink-0" />
                : <CheckCircle2  className="w-14 h-14 text-green-500 flex-shrink-0" />}
              <div>
                <p className={`text-4xl font-bold font-display ${isMalicious ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}`}>
                  {isMalicious ? 'MALICIOUS' : 'BENIGN'}
                </p>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{result.file_name}</p>
              </div>
            </div>
            {result.confidence != null && <ConfidenceGauge value={result.confidence} />}
          </div>
        </div>

        {/* File metadata */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-4">File Metadata</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              { icon: FileText,  label: 'Filename', val: result.file_name },
              { icon: HardDrive, label: 'Size', val: result.dump?.file_size ? `${(result.dump.file_size / 1024 / 1024).toFixed(2)} MB` : '—' },
              { icon: Calendar,  label: 'Analysed', val: result.classification_date ? new Date(result.classification_date).toLocaleString() : '—' },
              { icon: Hash,      label: 'SHA-256',  val: result.dump?.hash_value ? result.dump.hash_value.slice(0, 20) + '…' : '—' },
            ].map(({ icon: Icon, label, val }) => (
              <div key={label} className="flex items-start gap-2.5">
                <Icon className="w-4 h-4 text-gray-400 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-[10px] text-gray-400 uppercase tracking-wide">{label}</p>
                  <p className="text-sm text-gray-900 dark:text-white font-medium font-mono">{val}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Feature importance */}
        {top10.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-5">Top 10 Memory Artifacts (Feature Importance)</h3>
            <div className="space-y-3">
              {top10.map((f, i) => (
                <FeatureBar key={i} feature={f.feature} importance={f.importance} max={maxImp} />
              ))}
            </div>
          </div>
        )}

        {/* Suspicious artifacts */}
        {result.suspicious_artifacts?.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-4">Suspicious Artifacts</h3>
            <ul className="space-y-2">
              {result.suspicious_artifacts.map((a, i) => (
                <li key={i} className="flex items-start gap-2.5 text-sm text-gray-700 dark:text-gray-300">
                  <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
                  {typeof a === 'string' ? a : JSON.stringify(a)}
                </li>
              ))}
            </ul>
          </div>
        )}

        <Link to="/upload" className="inline-flex items-center text-sm text-blue-600 dark:text-blue-400 hover:underline">
          ← Upload another memory dump
        </Link>
      </div>
    </Layout>
  )
}
