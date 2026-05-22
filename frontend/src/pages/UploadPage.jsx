import { useState, useRef, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { FileUp, CheckCircle2, Loader2 } from 'lucide-react'
import Layout from '../components/Layout.jsx'
import api from '../utils/api.js'
import { useToast } from '../hooks/useToast.jsx'

const STAGES = ['uploading', 'validating', 'queued', 'processing', 'completed']

const DEFAULT_CONFIG = {
  allowed_extensions: ['.raw', '.mem', '.dmp', '.vmem', '.csv'],
  max_upload_bytes:   8 * 1024 * 1024 * 1024,
  max_upload_gb:      8,
}

export default function UploadPage() {
  const navigate = useNavigate()
  const inputRef = useRef(null)
  const toast    = useToast()
  const [drag,     setDrag]     = useState(false)
  const [file,     setFile]     = useState(null)
  const [stage,    setStage]    = useState(null)
  const [progress, setProgress] = useState(0)
  const [config,   setConfig]   = useState(DEFAULT_CONFIG)

  useEffect(() => {
    api.get('/analysis/config')
      .then(r => setConfig(r.data))
      .catch(() => {})
  }, [])

  const validate = useCallback((f) => {
    const ext = '.' + f.name.split('.').pop().toLowerCase()
    if (!config.allowed_extensions.includes(ext))
      return `Unsupported type "${ext}". Allowed: ${config.allowed_extensions.join(', ')}`
    if (f.size > config.max_upload_bytes)
      return `File exceeds the ${config.max_upload_gb} GB limit.`
    return null
  }, [config])

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

      let networkErrors = 0
      const poll = setInterval(async () => {
        try {
          const { data: res } = await api.get(`/analysis/results/${dumpId}`)
          networkErrors = 0
          if (res.status === 'complete') {
            clearInterval(poll)
            setStage('completed')
            toast.success('Analysis complete — loading results.')
            setTimeout(() => navigate(`/results/${dumpId}`), 1200)
          } else if (res.status === 'failed') {
            clearInterval(poll)
            setStage(null)
            toast.error('Analysis failed on the server. Please try again.')
          } else if (res.status === 'no_symbols') {
            clearInterval(poll)
            setStage(null)
            navigate(`/results/${dumpId}`)
          }
        } catch (_) {
          networkErrors += 1
          if (networkErrors >= 3) {
            clearInterval(poll)
            setStage(null)
            toast.error('Server connection lost. The analysis may have failed — check your reports.')
          }
        }
      }, 3000)
    } catch (e) {
      setStage(null)
      toast.error(e.response?.data?.message || 'Upload failed. Please try again.')
    }
  }, [navigate, toast, validate])

  const stageIdx  = STAGES.indexOf(stage)
  const acceptStr = config.allowed_extensions.join(',')
  const hintStr   = config.allowed_extensions.join(' · ') + ` — max ${config.max_upload_gb} GB`

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
            <input ref={inputRef} type="file" className="hidden" accept={acceptStr} onChange={e => { const f = e.target.files?.[0]; if (f) upload(f) }} />
            <div className="flex flex-col items-center gap-4">
              <div className="w-16 h-16 rounded-2xl bg-gray-100 dark:bg-gray-700 flex items-center justify-center">
                <FileUp className="w-8 h-8 text-gray-400" />
              </div>
              <div>
                <p className="font-medium text-gray-700 dark:text-gray-200">Drop memory dump here or click to browse</p>
                <p className="text-sm text-gray-400 dark:text-gray-500 mt-1">Accepts {hintStr}</p>
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
                Running Volatility forensic plugins — this may take several minutes for large dumps. Please keep this tab open.
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
