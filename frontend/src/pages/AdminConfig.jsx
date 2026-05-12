import { useState } from 'react'
import { Settings, Save, Check, ToggleLeft, ToggleRight } from 'lucide-react'
import Layout from '../components/Layout.jsx'

const DEFAULTS = {
  confidenceThreshold: 70,
  maxFileSizeMB: 2048,
  retrainSchedule: 'weekly',
  enableRF: true,
  enableFeatureExtraction: true,
  enableAuditLog: true,
  allowAnalystUpload: true,
}

function Toggle({ on, onToggle }) {
  return (
    <button onClick={onToggle} className="flex-shrink-0">
      {on
        ? <ToggleRight className="w-8 h-8 text-amber-500" />
        : <ToggleLeft  className="w-8 h-8 text-gray-400" />}
    </button>
  )
}

export default function AdminConfig() {
  const [cfg, setCfg] = useState(() => {
    try { return { ...DEFAULTS, ...JSON.parse(localStorage.getItem('memshield_config') || '{}') } }
    catch { return DEFAULTS }
  })
  const [saved, setSaved] = useState(false)

  function handleSave() {
    localStorage.setItem('memshield_config', JSON.stringify(cfg))
    setSaved(true)
    setTimeout(() => setSaved(false), 2500)
  }

  function set(key, val) { setCfg(c => ({ ...c, [key]: val })) }

  return (
    <Layout>
      <div className="space-y-6 max-w-2xl">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white tracking-tight">System Configuration</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1 text-sm">Adjust analysis and system settings</p>
        </div>

        {/* Thresholds */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-6 shadow-sm space-y-6">
          <h2 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-2">
            <Settings className="w-3.5 h-3.5" /> Analysis Thresholds
          </h2>

          {/* Confidence threshold */}
          <div>
            <div className="flex justify-between mb-2">
              <label className="text-sm font-medium text-gray-700 dark:text-gray-300">Confidence Threshold</label>
              <span className="text-sm font-mono font-bold text-amber-600 dark:text-amber-400">{cfg.confidenceThreshold}%</span>
            </div>
            <input
              type="range" min="50" max="99" step="1"
              value={cfg.confidenceThreshold}
              onChange={e => set('confidenceThreshold', Number(e.target.value))}
              className="w-full accent-amber-500 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-gray-400 mt-1">
              <span>50% (sensitive)</span><span>99% (strict)</span>
            </div>
          </div>

          {/* Max file size */}
          <div>
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300 block mb-2">
              Max Upload Size (MB)
            </label>
            <input
              type="number" min="64" max="4096" step="64"
              value={cfg.maxFileSizeMB}
              onChange={e => set('maxFileSizeMB', Number(e.target.value))}
              className="input-field max-w-[140px] text-sm font-mono"
            />
          </div>

          {/* Retrain schedule */}
          <div>
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300 block mb-2">
              Retraining Schedule
            </label>
            <select
              value={cfg.retrainSchedule}
              onChange={e => set('retrainSchedule', e.target.value)}
              className="input-field max-w-[200px] text-sm"
            >
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
              <option value="manual">Manual only</option>
            </select>
          </div>
        </div>

        {/* Feature toggles */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-6 shadow-sm space-y-4">
          <h2 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Feature Toggles</h2>

          {[
            { key: 'enableRF',               label: 'Random Forest Classifier',    desc: 'Main classification model' },
            { key: 'enableFeatureExtraction', label: 'Volatility Feature Extraction', desc: 'Run Volatility plugins on uploads' },
            { key: 'enableAuditLog',          label: 'Audit Logging',               desc: 'Record all user actions' },
            { key: 'allowAnalystUpload',      label: 'Analyst Uploads',             desc: 'Allow forensic_analyst role to upload dumps' },
          ].map(({ key, label, desc }) => (
            <div key={key} className="flex items-center justify-between gap-4 py-2 border-b border-gray-100 dark:border-gray-700 last:border-0">
              <div>
                <p className="text-sm font-medium text-gray-800 dark:text-gray-200">{label}</p>
                <p className="text-xs text-gray-400 mt-0.5">{desc}</p>
              </div>
              <Toggle on={cfg[key]} onToggle={() => set(key, !cfg[key])} />
            </div>
          ))}
        </div>

        {/* Save */}
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-6 py-3 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-sm font-medium transition-colors"
        >
          {saved ? <Check className="w-4 h-4" /> : <Save className="w-4 h-4" />}
          {saved ? 'Saved!' : 'Save Configuration'}
        </button>
        <p className="text-xs text-gray-400">Configuration is stored locally. Backend API persistence coming in a future update.</p>
      </div>
    </Layout>
  )
}
