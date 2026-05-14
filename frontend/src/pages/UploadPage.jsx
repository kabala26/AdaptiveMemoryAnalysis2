import { useState, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { FileUp, CheckCircle2, Loader2 } from 'lucide-react'
import Layout from '../components/Layout.jsx'
import api from '../utils/api.js'
import { useToast } from '../hooks/useToast.jsx'

const ALLOWED = ['.raw', '.mem', '.dmp', '.vmem', '.csv']
const MAX_BYTES = 8 * 1024 * 1024 * 1024
const STAGES = ['uploading', 'validating', 'queued', 'processing', 'completed']

function validate(file) {
  const ext = '.' + file.name.split('.').pop().toLowerCase()
  if (!ALLOWED.includes(ext)) return `Unsupported type "${ext}". Allowed: ${ALLOWED.join(', ')}`
  if (file.size > MAX_BYTES) return 'File exceeds the 8 GB limit.'
  return null
}

export default function UploadPage() {
  const navigate = useNavigate()
  const inputRef = useRef(null)
  const toast    = useToast()
  const [drag,     setDrag]     = useState(false)
  const [file,     setFile]     = useState(null)
  const [stage,    setStage]    = useState(null)
  const [progress, setProgress] = useState(0)

  const upload = useCallback(async (f) => {
    const err = validate(f)
    if (err) { toast.error(err); return }

    setFile(f); setStage('uploading'); setProgress(0)

    const form = new FormData()
    form.append('file', f)

    try {
      const { data } = await api.post('/analysis/upload', form, {
        onUploadProgress: e => setProgress(Math.round((e.loaded / (e.total || 1)) * 100)),
      })

      const dumpId = data.dump_id
      setStage('validating')
      await delay(700)
      setStage('queued')

      await api.post('/analysis/analyze', { dump_id: dumpId })
      setStage('processing')

      const poll = setInterval(async () => {
        try {
          const { data: res } = await api.get(`/analysis/results/${dumpId}`)
          if (res.status === 'complete') {
            clearInterval(poll)
            setStage('completed')
            toast.success('Analysis complete — loading results.')
            setTimeout(() => navigate(`/results/${dumpId}`), 1200)
          } else if (res.status === 'failed') {
            clearInterval(poll)
            setStage(null)
            toast.error('Analysis failed on the server. Please try again.')
          }
        } catch (_) {}
      }, 3000)
    } catch (e) {
      setStage(null)
      toast.error(e.response?.data?.message || 'Upload failed. Please try again.')
    }
  }, [navigate, toast])

  const stageIdx = STAGES.indexOf(stage)

  return (
    <Layout>
      <div className="max-w-2xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white tracking-tight">Upload Memory Dump</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1 text-sm">Submit a raw memory image for forensic classification</p>
        </div>

        {/* Drop zone */}
        {!stage && (
          <div
            onDragOver={e => { e.preventDefault(); setDrag(true) }}
            onDragLeave={() => setDrag(false)}
            onDrop={e => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files?.[0]; if (f) upload(f) }}
            onClick={() => inputRef.current?.click()}
            className={`rounded-2xl p-16 border-2 transition-all duration-200 cursor-pointer text-center ${
              drag
                ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/10'
                : 'border-dashed border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 hover:border-blue-400 dark:hover:border-blue-500'
            }`}
          >
            <input ref={inputRef} type="file" className="hidden" accept=".raw,.mem,.dmp,.vmem,.csv" onChange={e => { const f = e.target.files?.[0]; if (f) upload(f) }} />
            <div className="flex flex-col items-center gap-4">
              <div className="w-16 h-16 rounded-2xl bg-gray-100 dark:bg-gray-700 flex items-center justify-center">
                <FileUp className="w-8 h-8 text-gray-400" />
              </div>
              <div>
                <p className="font-medium text-gray-700 dark:text-gray-200">Drop memory dump here or click to browse</p>
                <p className="text-sm text-gray-400 dark:text-gray-500 mt-1">Accepts .raw · .mem · .dmp · .vmem · .csv — max 8 GB</p>
              </div>
            </div>
          </div>
        )}

        {/* Progress card */}
        {stage && (
          <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-8">
            <div className="flex items-center gap-3 mb-6">
              <FileUp className="w-5 h-5 text-gray-400 flex-shrink-0" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-200 truncate">{file?.name}</span>
              <span className="ml-auto text-xs text-gray-400 font-mono">{(file?.size / 1024 / 1024).toFixed(1)} MB</span>
            </div>

            {/* Upload bar */}
            {stage === 'uploading' && (
              <div className="mb-6">
                <div className="flex justify-between text-xs text-gray-500 mb-1.5">
                  <span>Uploading…</span>
                  <span className="font-mono">{progress}%</span>
                </div>
                <div className="h-2 bg-gray-100 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div className="h-full bg-blue-500 rounded-full transition-all duration-300" style={{ width: `${progress}%` }} />
                </div>
              </div>
            )}

            {/* Stage list */}
            <div className="space-y-3">
              {STAGES.map((s, i) => {
                const done   = i < stageIdx
                const active = i === stageIdx
                return (
                  <div key={s} className="flex items-center gap-3">
                    <div className={`w-6 h-6 rounded-full flex-shrink-0 flex items-center justify-center transition-all ${
                      done   ? 'bg-green-500' :
                      active ? 'bg-blue-500'  : 'bg-gray-200 dark:bg-gray-700'
                    }`}>
                      {done   ? <CheckCircle2 className="w-4 h-4 text-white" /> :
                       active ? <Loader2 className="w-3.5 h-3.5 text-white animate-spin" /> :
                                <span className="w-2 h-2 rounded-full bg-gray-400 dark:bg-gray-500" />}
                    </div>
                    <span className={`text-sm capitalize ${
                      done   ? 'text-green-600 dark:text-green-400' :
                      active ? 'text-blue-600 dark:text-blue-400 font-medium' :
                               'text-gray-400 dark:text-gray-500'
                    }`}>{s}</span>
                  </div>
                )
              })}
            </div>

            {stage === 'processing' && (
              <p className="mt-4 text-xs text-gray-400 dark:text-gray-500 flex items-center gap-1.5">
                <Loader2 className="w-3 h-3 animate-spin flex-shrink-0" />
                Running Volatility forensic plugins — this takes <strong className="text-gray-500 dark:text-gray-400">3–10 minutes</strong> for a typical memory dump. Please keep this tab open.
              </p>
            )}

            {stage === 'completed' && (
              <p className="mt-6 text-sm text-green-600 dark:text-green-400 font-medium flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" /> Analysis complete — redirecting to results…
              </p>
            )}
          </div>
        )}
      </div>
    </Layout>
  )
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)) }
