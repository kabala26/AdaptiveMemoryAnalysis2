import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { AlertTriangle, CheckCircle2, FileText, Calendar, HardDrive, Hash, Loader2, Shield, Bug, DatabaseZap, RefreshCw } from 'lucide-react'
import Layout from '../components/Layout.jsx'
import api from '../utils/api.js'

// ── Colour maps ───────────────────────────────────────────────────────────────

const CATEGORY_COLORS = {
  Ransomware: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 border-red-300 dark:border-red-700',
  Spyware:    'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 border-purple-300 dark:border-purple-700',
  Trojan:     'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 border-orange-300 dark:border-orange-700',
}
const CATEGORY_BAR_COLORS = {
  Ransomware: 'bg-red-500',
  Spyware:    'bg-purple-500',
  Trojan:     'bg-orange-500',
}
const DEFAULT_CATEGORY_COLOR = 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600'

// ── Reusable components ───────────────────────────────────────────────────────

function CategoryBadge({ category }) {
  const cls = CATEGORY_COLORS[category] || DEFAULT_CATEGORY_COLOR
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wide border ${cls}`}>
      <Shield className="w-3 h-3" /> {category}
    </span>
  )
}

function ConfidenceGauge({ value }) {
  const pct = Math.round((value ?? 0) * 100)
  const color = pct >= 80 ? '#22c55e' : pct >= 60 ? '#f59e0b' : '#ef4444'
  const rotation = -90 + (pct / 100) * 180
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="120" height="68" viewBox="0 0 120 68">
        <path d="M10 60 A50 50 0 0 1 110 60" fill="none" stroke="#e5e7eb" strokeWidth="12" strokeLinecap="round" className="dark:[stroke:#374151]" />
        <path d="M10 60 A50 50 0 0 1 110 60" fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={`${(pct / 100) * 157} 157`} />
        <line x1="60" y1="60" x2="60" y2="18" stroke={color} strokeWidth="3" strokeLinecap="round"
          style={{ transformOrigin: '60px 60px', transform: `rotate(${rotation}deg)` }} />
        <circle cx="60" cy="60" r="4" fill={color} />
      </svg>
      <p className="text-3xl font-bold font-mono" style={{ color }}>{pct}%</p>
      <p className="text-xs text-gray-400">Confidence score</p>
    </div>
  )
}

function FeatureBar({ feature, importance, max, value }) {
  const pct = max > 0 ? (importance / max) * 100 : 0
  return (
    <div className="flex items-center gap-3 group">
      <span className="text-xs font-mono text-gray-500 dark:text-gray-400 w-40 flex-shrink-0 truncate" title={feature}>{feature}</span>
      <div className="flex-1 h-2 bg-gray-100 dark:bg-gray-700 rounded-full overflow-hidden">
        <div className="h-full bg-blue-500 rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-gray-400 w-14 text-right">{(importance * 100).toFixed(2)}%</span>
      {value != null && (
        <span className="text-xs font-mono text-amber-500 dark:text-amber-400 w-16 text-right" title="Value extracted from this dump">
          {Number.isInteger(value) ? value : value.toFixed(1)}
        </span>
      )}
    </div>
  )
}

/** Horizontal bar row for ranked malware lists */
function RankBar({ label, confidence, color = 'bg-amber-500', badge = null }) {
  const pct = Math.round((confidence ?? 0) * 100)
  return (
    <div className="flex items-center gap-3">
      <div className="w-32 flex-shrink-0 flex items-center gap-1.5">
        {badge}
        <span className="text-xs font-mono text-gray-700 dark:text-gray-300 truncate">{label}</span>
      </div>
      <div className="flex-1 h-2 bg-gray-100 dark:bg-gray-700 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-gray-500 dark:text-gray-400 w-10 text-right">{pct}%</span>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

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

  // ── Missing symbol table ──────────────────────────────────────────────────
  if (result?.status === 'no_symbols') {
    const d = result.no_symbols_detail || {}
    return (
      <Layout>
        <div className="max-w-2xl mx-auto mt-16 space-y-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-100 dark:bg-amber-900/30 flex items-center justify-center flex-shrink-0">
              <DatabaseZap className="w-5 h-5 text-amber-600 dark:text-amber-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-gray-900 dark:text-white">Symbol Table Not Found</h1>
              <p className="text-sm text-gray-500 dark:text-gray-400">Analysis could not proceed — Windows kernel symbols are missing</p>
            </div>
          </div>

          <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700 rounded-2xl p-6 space-y-4">
            <p className="text-sm text-amber-800 dark:text-amber-300 leading-relaxed">
              Volatility 3 requires a symbol table (ISF file) that matches the exact Windows kernel
              build inside this memory dump. No matching file was found on this server, and
              auto-download from Microsoft's symbol server either failed or was not attempted yet.
            </p>

            {(d.pdb_name || d.guid) && (
              <div className="bg-white dark:bg-gray-800 rounded-xl border border-amber-200 dark:border-amber-700 p-4 space-y-2">
                <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Kernel build info extracted from dump</p>
                {d.pdb_name && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-500 dark:text-gray-400 w-20">PDB Name</span>
                    <code className="text-xs font-mono bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">{d.pdb_name}</code>
                  </div>
                )}
                {d.guid && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-500 dark:text-gray-400 w-20">GUID</span>
                    <code className="text-xs font-mono bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded break-all">{d.guid}</code>
                  </div>
                )}
              </div>
            )}

            <div className="space-y-2">
              <p className="text-xs font-bold text-amber-700 dark:text-amber-400 uppercase tracking-wide">How to fix (admin action required)</p>
              <ol className="text-sm text-amber-800 dark:text-amber-300 space-y-1.5 list-decimal list-inside">
                <li>
                  Run <code className="text-xs bg-white dark:bg-gray-800 px-1.5 py-0.5 rounded border border-amber-200 dark:border-amber-700">venv/bin/python download_symbols.py</code> on
                  the server to install the full Volatility 3 symbol pack (~600 MB).
                </li>
                <li>
                  Or re-submit this dump — Volatility will attempt to auto-download the specific
                  symbol file for this kernel build from Microsoft's symbol server.
                </li>
              </ol>
            </div>
          </div>

          <div className="flex gap-3">
            <Link to="/upload" className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm text-gray-600 dark:text-gray-400 border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
              ← Upload another
            </Link>
            <Link
              to="/upload"
              className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm bg-amber-600 hover:bg-amber-500 text-white font-medium transition-colors"
            >
              <RefreshCw className="w-4 h-4" /> Re-upload &amp; retry
            </Link>
          </div>
        </div>
      </Layout>
    )
  }

  if (result?.status === 'failed') return (
    <Layout>
      <div className="max-w-lg mx-auto mt-20 text-center">
        <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <p className="text-gray-900 dark:text-white font-semibold mb-1">Analysis Failed</p>
        <p className="text-gray-500 dark:text-gray-400 text-sm mb-4">The server could not complete analysis for this dump. This may be due to a corrupted file or an internal error.</p>
        <Link to="/upload" className="inline-block text-sm text-blue-600 dark:text-blue-400 underline">← Upload another</Link>
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

  // ── CSV batch results ─────────────────────────────────────────────────────
  if (result.is_batch && result.batch_summary) {
    const bs = result.batch_summary
    const catEntries = Object.entries(bs.categories || {}).sort((a, b) => b[1] - a[1])
    const famEntries = Object.entries(bs.families   || {}).sort((a, b) => b[1] - a[1])

    return (
      <Layout>
        <div className="max-w-3xl mx-auto space-y-5">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white tracking-tight">Batch Analysis Results</h1>
            <p className="text-gray-500 dark:text-gray-400 mt-1 text-sm">{result.file_name}</p>
          </div>

          {/* Overview stat tiles */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: 'Total Samples',  value: bs.total.toLocaleString(),         color: 'text-gray-900 dark:text-white' },
              { label: 'Benign',          value: bs.benign_count.toLocaleString(),  color: 'text-green-600 dark:text-green-400' },
              { label: 'Malware',         value: bs.malware_count.toLocaleString(), color: 'text-red-600 dark:text-red-400' },
              { label: 'Detection Rate',  value: `${bs.malware_pct}%`,              color: bs.malware_pct > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400' },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-5 shadow-sm">
                <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-1">{label}</p>
                <p className={`text-2xl font-bold font-mono ${color}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Malware by category */}
          {catEntries.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-6 shadow-sm">
              <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                <Shield className="w-3.5 h-3.5" /> Malware by Category
              </h3>
              <div className="space-y-3">
                {catEntries.map(([cat, count]) => {
                  const pct = bs.malware_count > 0 ? (count / bs.malware_count) * 100 : 0
                  return (
                    <div key={cat} className="flex items-center gap-3">
                      <div className="w-32 flex-shrink-0"><CategoryBadge category={cat} /></div>
                      <div className="flex-1 h-2 bg-gray-100 dark:bg-gray-700 rounded-full overflow-hidden">
                        <div className={`h-full ${CATEGORY_BAR_COLORS[cat] || 'bg-gray-500'} rounded-full`} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-xs font-mono text-gray-500 w-28 text-right">
                        {count.toLocaleString()} ({pct.toFixed(1)}%)
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* All detected malware families */}
          {famEntries.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-6 shadow-sm">
              <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                <Bug className="w-3.5 h-3.5" /> All Detected Malware Families ({famEntries.length})
              </h3>
              <div className="space-y-2.5">
                {famEntries.map(([fam, count]) => {
                  const pct = bs.malware_count > 0 ? (count / bs.malware_count) * 100 : 0
                  return (
                    <div key={fam} className="flex items-center gap-3">
                      <span className="text-xs font-mono text-gray-700 dark:text-gray-300 w-32 flex-shrink-0 truncate">{fam}</span>
                      <div className="flex-1 h-2 bg-gray-100 dark:bg-gray-700 rounded-full overflow-hidden">
                        <div className="h-full bg-amber-500 rounded-full" style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-xs font-mono text-gray-400 w-28 text-right">
                        {count.toLocaleString()} ({pct.toFixed(1)}%)
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

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

          <Link to="/upload" className="inline-flex items-center text-sm text-blue-600 dark:text-blue-400 hover:underline">
            ← Upload another file
          </Link>
        </div>
      </Layout>
    )
  }

  // ── Single memory dump results ────────────────────────────────────────────
  const isMalicious = result.prediction === 'Malware'
  const top10 = (result.feature_importance || []).slice(0, 10)
  const maxImp = top10[0]?.importance || 1
  const dumpValueMap = Object.fromEntries(
    (result.dump_feature_values || []).map(f => [f.feature, f.value])
  )

  const categoryRankings = result.category_rankings || []
  const familyRankings   = result.family_rankings   || []

  return (
    <Layout>
      <div className="max-w-3xl mx-auto space-y-5">

        {/* Verdict banner */}
        <div className={`rounded-2xl border-2 p-8 ${
          isMalicious ? 'border-red-400 bg-red-50 dark:bg-red-900/10'
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
                {isMalicious && result.malware_category && (
                  <div className="mt-2.5 flex flex-wrap items-center gap-2">
                    <CategoryBadge category={result.malware_category} />
                    {result.malware_family && (
                      <span className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wide border bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 border-gray-300 dark:border-gray-600">
                        <Bug className="w-3 h-3" /> {result.malware_family}
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>
            {result.confidence != null && <ConfidenceGauge value={result.confidence} />}
          </div>
        </div>

        {/* Full malware classification — categories + ranked families */}
        {isMalicious && (categoryRankings.length > 0 || familyRankings.length > 0) && (
          <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-6 space-y-6">
            <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Malware Classification</h3>

            {categoryRankings.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 mb-3 flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5" /> Category probabilities
                </p>
                <div className="space-y-2.5">
                  {categoryRankings.map(({ category, confidence }, i) => (
                    <RankBar
                      key={category}
                      label={category}
                      confidence={confidence}
                      color={CATEGORY_BAR_COLORS[category] || 'bg-gray-400'}
                      badge={i === 0 ? <CategoryBadge category={category} /> : null}
                    />
                  ))}
                </div>
              </div>
            )}

            {familyRankings.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 mb-3 flex items-center gap-1.5">
                  <Bug className="w-3.5 h-3.5" /> Family probabilities — {familyRankings.length} candidate{familyRankings.length > 1 ? 's' : ''} detected
                </p>
                <div className="space-y-2.5">
                  {familyRankings.map(({ family, confidence }) => (
                    <RankBar key={family} label={family} confidence={confidence} color="bg-amber-500" />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

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
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Top 10 Memory Artifacts (Feature Importance)</h3>
              <div className="flex gap-4 text-[10px] text-gray-400">
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500 inline-block" /> Model weight</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-400 inline-block" /> This dump</span>
              </div>
            </div>
            <div className="space-y-3">
              {top10.map((f, i) => (
                <FeatureBar key={i} feature={f.feature} importance={f.importance} max={maxImp} value={dumpValueMap[f.feature]} />
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
