import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Clock } from 'lucide-react'
import { useAuth } from '../hooks/useAuth.jsx'

const WARNING_MS = 25 * 60 * 1000  // 25 min → show modal
const TIMEOUT_MS = 30 * 60 * 1000  // 30 min → auto logout
const COUNTDOWN  = (TIMEOUT_MS - WARNING_MS) / 1000  // 300 s

export default function SessionTimeoutModal() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [visible,   setVisible]   = useState(false)
  const [remaining, setRemaining] = useState(COUNTDOWN)

  const warnTimer    = useRef(null)
  const logoutTimer  = useRef(null)
  const tickInterval = useRef(null)

  const reset = useCallback(() => {
    setVisible(false)
    setRemaining(COUNTDOWN)
    clearTimeout(warnTimer.current)
    clearTimeout(logoutTimer.current)
    clearInterval(tickInterval.current)

    warnTimer.current = setTimeout(() => {
      setVisible(true)
      setRemaining(COUNTDOWN)
      tickInterval.current = setInterval(() => {
        setRemaining(s => Math.max(0, s - 1))
      }, 1000)
    }, WARNING_MS)

    logoutTimer.current = setTimeout(async () => {
      clearInterval(tickInterval.current)
      await logout()
      navigate('/auth', { replace: true })
    }, TIMEOUT_MS)
  }, [logout, navigate])

  useEffect(() => {
    if (!user) return
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart']
    events.forEach(e => window.addEventListener(e, reset, { passive: true }))
    reset()
    return () => {
      events.forEach(e => window.removeEventListener(e, reset))
      clearTimeout(warnTimer.current)
      clearTimeout(logoutTimer.current)
      clearInterval(tickInterval.current)
    }
  }, [user, reset])

  if (!visible || !user) return null

  const mins = String(Math.floor(remaining / 60)).padStart(2, '0')
  const secs = String(remaining % 60).padStart(2, '0')

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl border border-gray-200 dark:border-gray-700 p-8 max-w-sm w-full mx-4">
        <div className="flex flex-col items-center text-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-amber-100 dark:bg-amber-900/30 flex items-center justify-center">
            <Clock className="w-7 h-7 text-amber-600 dark:text-amber-400" />
          </div>
          <div>
            <h3 className="font-display text-xl text-gray-900 dark:text-white">Session expiring</h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              You will be signed out in{' '}
              <span className="font-mono font-bold text-amber-600 dark:text-amber-400">{mins}:{secs}</span>{' '}
              due to inactivity.
            </p>
          </div>
          <div className="flex gap-3 w-full">
            <button
              onClick={reset}
              className="flex-1 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium transition-colors"
            >
              Stay signed in
            </button>
            <button
              onClick={async () => { await logout(); navigate('/auth', { replace: true }) }}
              className="flex-1 py-3 rounded-xl border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 text-sm hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            >
              Sign out
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
