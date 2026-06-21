import { useState } from 'react'
import { Eye, EyeOff, Loader2, AlertCircle } from 'lucide-react'
import { useAuth } from '../hooks/useAuth.jsx'
import api from '../utils/api.js'
import { validateLoginForm } from '../utils/validation.js'

export default function LoginForm() {
  const { login }                     = useAuth()
  const [values, setValues]           = useState({ email: '', password: '' })
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
    const errs = validateLoginForm(values)
    if (Object.keys(errs).length) { setErrors(errs); return }

    setLoading(true)
    setServerError('')
    try {
      const { data } = await api.post('/auth/login', values)
      login({ access_token: data.access_token, refresh_token: data.refresh_token }, data.user)
    } catch (err) {
      const msg = err.response?.data?.message || 'Invalid credentials. Please try again.'
      setServerError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="space-y-4" aria-label="Email sign in form">

      {/* Server-level error */}
      {serverError && (
        <div role="alert" className="flex items-start gap-2 text-sm text-red-600 bg-red-50 border border-red-200 rounded-xl px-3 py-2.5">
          <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <span>{serverError}</span>
        </div>
      )}

      {/* Email */}
      <div>
        <label htmlFor="login-email" className="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1.5 font-mono tracking-wide uppercase">
          Email
        </label>
        <input
          id="login-email"
          type="email"
          name="email"
          autoComplete="email"
          value={values.email}
          onChange={handleChange}
          placeholder="you@example.com"
          className={`input-field ${errors.email ? 'error' : ''}`}
          aria-invalid={!!errors.email}
          aria-describedby={errors.email ? 'login-email-error' : undefined}
        />
        {errors.email && (
          <p id="login-email-error" className="error-message">
            <AlertCircle className="w-3 h-3" />
            {errors.email}
          </p>
        )}
      </div>

      {/* Password */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label htmlFor="login-password" className="block text-xs font-medium text-gray-600 dark:text-gray-300 font-mono tracking-wide uppercase">
            Password
          </label>

        </div>
        <div className="relative">
          <input
            id="login-password"
            type={showPw ? 'text' : 'password'}
            name="password"
            autoComplete="current-password"
            value={values.password}
            onChange={handleChange}
            placeholder="••••••••"
            className={`input-field pr-11 ${errors.password ? 'error' : ''}`}
            aria-invalid={!!errors.password}
            aria-describedby={errors.password ? 'login-pw-error' : undefined}
          />
          <button
            type="button"
            onClick={() => setShowPw(s => !s)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
            aria-label={showPw ? 'Hide password' : 'Show password'}
          >
            {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        </div>
        {errors.password && (
          <p id="login-pw-error" className="error-message">
            <AlertCircle className="w-3 h-3" />
            {errors.password}
          </p>
        )}
      </div>

      <button type="submit" disabled={loading} className="btn-primary mt-2">
        {loading
          ? <><Loader2 className="w-4 h-4 animate-spin-slow" />Signing in…</>
          : 'Sign in'}
      </button>
    </form>
  )
}
