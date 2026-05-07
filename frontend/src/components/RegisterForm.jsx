import { useState } from 'react'
import { Eye, EyeOff, Loader2, AlertCircle, CheckCircle2 } from 'lucide-react'
import { useAuth } from '../hooks/useAuth.jsx'
import api from '../utils/api.js'
import { validateRegisterForm } from '../utils/validation.js'

const PW_RULES = [
  { label: '8+ characters', test: p => p.length >= 8 },
  { label: 'Uppercase letter', test: p => /[A-Z]/.test(p) },
  { label: 'Number', test: p => /[0-9]/.test(p) },
]

export default function RegisterForm() {
  const { login }                     = useAuth()
  const [values, setValues]           = useState({ name: '', email: '', password: '' })
  const [errors, setErrors]           = useState({})
  const [showPw, setShowPw]           = useState(false)
  const [loading, setLoading]         = useState(false)
  const [serverError, setServerError] = useState('')

  function handleChange(e) {
    const { name, value } = e.target
    setValues(v => ({ ...v, [name]: value }))
    if (errors[name]) setErrors(er => ({ ...er, [name]: '' }))
    setServerError('')
  }

  async function handleSubmit(e) {
    e.preventDefault()
    const errs = validateRegisterForm(values)
    if (Object.keys(errs).length) { setErrors(errs); return }

    setLoading(true)
    setServerError('')
    try {
      const { data } = await api.post('/auth/register', values)
      login({ access_token: data.access_token, refresh_token: data.refresh_token }, data.user)
    } catch (err) {
      const msg = err.response?.data?.message || 'Registration failed. Please try again.'
      setServerError(msg)
    } finally {
      setLoading(false)
    }
  }

  const pwStrength = PW_RULES.filter(r => r.test(values.password))

  return (
    <form onSubmit={handleSubmit} noValidate className="space-y-4" aria-label="Create account form">

      {serverError && (
        <div role="alert" className="flex items-start gap-2 text-sm text-red-600 bg-red-50 border border-red-200 rounded-xl px-3 py-2.5">
          <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <span>{serverError}</span>
        </div>
      )}

      {/* Name */}
      <div>
        <label htmlFor="reg-name" className="block text-xs font-medium text-ink-600 mb-1.5 font-mono tracking-wide uppercase">
          Full Name
        </label>
        <input
          id="reg-name"
          type="text"
          name="name"
          autoComplete="name"
          value={values.name}
          onChange={handleChange}
          placeholder="Ada Lovelace"
          className={`input-field ${errors.name ? 'error' : ''}`}
          aria-invalid={!!errors.name}
        />
        {errors.name && (
          <p className="error-message"><AlertCircle className="w-3 h-3" />{errors.name}</p>
        )}
      </div>

      {/* Email */}
      <div>
        <label htmlFor="reg-email" className="block text-xs font-medium text-ink-600 mb-1.5 font-mono tracking-wide uppercase">
          Email
        </label>
        <input
          id="reg-email"
          type="email"
          name="email"
          autoComplete="email"
          value={values.email}
          onChange={handleChange}
          placeholder="you@example.com"
          className={`input-field ${errors.email ? 'error' : ''}`}
          aria-invalid={!!errors.email}
        />
        {errors.email && (
          <p className="error-message"><AlertCircle className="w-3 h-3" />{errors.email}</p>
        )}
      </div>

      {/* Password with strength indicator */}
      <div>
        <label htmlFor="reg-password" className="block text-xs font-medium text-ink-600 mb-1.5 font-mono tracking-wide uppercase">
          Password
        </label>
        <div className="relative">
          <input
            id="reg-password"
            type={showPw ? 'text' : 'password'}
            name="password"
            autoComplete="new-password"
            value={values.password}
            onChange={handleChange}
            placeholder="Create a strong password"
            className={`input-field pr-11 ${errors.password ? 'error' : ''}`}
            aria-invalid={!!errors.password}
          />
          <button
            type="button"
            onClick={() => setShowPw(s => !s)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-ink-400 hover:text-ink-700 transition-colors"
            aria-label={showPw ? 'Hide password' : 'Show password'}
          >
            {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        </div>
        {errors.password && (
          <p className="error-message"><AlertCircle className="w-3 h-3" />{errors.password}</p>
        )}

        {/* Strength rules */}
        {values.password.length > 0 && (
          <ul className="mt-2 grid grid-cols-3 gap-1.5" aria-label="Password requirements">
            {PW_RULES.map(rule => {
              const pass = rule.test(values.password)
              return (
                <li key={rule.label} className={`flex items-center gap-1 text-[10px] font-mono transition-colors ${pass ? 'text-green-600' : 'text-ink-400'}`}>
                  <CheckCircle2 className={`w-3 h-3 flex-shrink-0 transition-opacity ${pass ? 'opacity-100' : 'opacity-30'}`} />
                  {rule.label}
                </li>
              )
            })}
          </ul>
        )}
      </div>

      <button type="submit" disabled={loading} className="btn-primary mt-2">
        {loading
          ? <><Loader2 className="w-4 h-4 animate-spin-slow" />Creating account…</>
          : 'Create account'}
      </button>
    </form>
  )
}
