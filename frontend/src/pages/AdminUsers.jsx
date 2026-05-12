import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth.jsx'
import { Users, Shield, UserX, Check, Loader2 } from 'lucide-react'
import Layout from '../components/Layout.jsx'
import api from '../utils/api.js'

function RoleBadge({ role }) {
  return role === 'admin'
    ? <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400 uppercase">Admin</span>
    : <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 uppercase">Analyst</span>
}

export default function AdminUsers() {
  const { user: me }            = useAuth()
  const [users,   setUsers]     = useState([])
  const [loading, setLoading]   = useState(true)
  const [saving,  setSaving]    = useState(null)  // user id being updated
  const [toast,   setToast]     = useState(null)

  function showToast(msg) { setToast(msg); setTimeout(() => setToast(null), 3000) }

  useEffect(() => {
    api.get('/auth/users')
      .then(r => setUsers(r.data.users || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  async function handleRoleChange(userId, newRole) {
    setSaving(userId)
    try {
      await api.post(`/auth/users/${userId}/role`, { role: newRole })
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, role: newRole } : u))
      showToast('Role updated.')
    } catch (e) {
      showToast(e.response?.data?.message || 'Failed to update role.')
    } finally {
      setSaving(null)
    }
  }

  async function handleDeactivate(userId, active) {
    // API endpoint for deactivation would be /auth/users/<id>/deactivate
    // Placeholder — wire up when backend endpoint is ready
    showToast('Account status change coming soon.')
  }

  const stats = {
    total:   users.length,
    admins:  users.filter(u => u.role === 'admin').length,
    analysts:users.filter(u => u.role === 'forensic_analyst').length,
    active:  users.filter(u => u.is_active).length,
  }

  return (
    <Layout>
      <div className="space-y-6 max-w-5xl">
        {/* Toast */}
        {toast && (
          <div className="fixed top-6 right-6 z-50 px-4 py-3 rounded-xl bg-gray-900 dark:bg-gray-700 text-white text-sm shadow-xl flex items-center gap-2">
            <Check className="w-4 h-4 text-green-400" /> {toast}
          </div>
        )}

        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white tracking-tight">User Management</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1 text-sm">Manage roles and account status</p>
        </div>

        {/* Quick stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Total Users', value: stats.total },
            { label: 'Admins',      value: stats.admins },
            { label: 'Analysts',    value: stats.analysts },
            { label: 'Active',      value: stats.active },
          ].map(s => (
            <div key={s.label} className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-5 text-center shadow-sm">
              <p className="text-[10px] text-gray-400 uppercase tracking-widest">{s.label}</p>
              <p className="text-2xl font-bold font-mono text-amber-600 dark:text-amber-400 mt-1">{loading ? '—' : s.value}</p>
            </div>
          ))}
        </div>

        {/* User table */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
            <h2 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-2">
              <Users className="w-3.5 h-3.5" /> All Users
            </h2>
          </div>

          {loading ? (
            <div className="py-16 flex items-center justify-center gap-3 text-gray-400">
              <Loader2 className="w-5 h-5 animate-spin" /> Loading users…
            </div>
          ) : (
            <div className="divide-y divide-gray-100 dark:divide-gray-700">
              {users.map(u => (
                <div key={u.id} className="flex items-center gap-4 px-6 py-4 hover:bg-amber-50/30 dark:hover:bg-amber-900/10 transition-colors">
                  {/* Avatar */}
                  <div className="w-10 h-10 rounded-xl bg-gray-200 dark:bg-gray-700 flex items-center justify-center text-sm font-bold text-gray-600 dark:text-gray-300 flex-shrink-0">
                    {u.name.charAt(0).toUpperCase()}
                  </div>

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-gray-900 dark:text-white truncate">{u.name}</p>
                      {!u.is_active && <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-red-100 text-red-500 dark:bg-red-900/20">Inactive</span>}
                    </div>
                    <p className="text-xs text-gray-400 mt-0.5 truncate">{u.email}</p>
                    <p className="text-[10px] text-gray-300 dark:text-gray-600 mt-0.5">
                      {u.last_login_at ? `Last login: ${new Date(u.last_login_at).toLocaleDateString()}` : 'Never logged in'}
                    </p>
                  </div>

                  {/* Role badge */}
                  <RoleBadge role={u.role} />

                  {/* Role selector */}
                  <select
                    value={u.role}
                    disabled={u.id === me?.id || saving === u.id}
                    onChange={e => handleRoleChange(u.id, e.target.value)}
                    className="text-xs px-2.5 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-200 disabled:opacity-50 cursor-pointer focus:outline-none focus:ring-2 focus:ring-amber-400"
                  >
                    <option value="forensic_analyst">Forensic Analyst</option>
                    <option value="admin">Admin</option>
                  </select>

                  {saving === u.id && <Loader2 className="w-4 h-4 text-gray-400 animate-spin flex-shrink-0" />}

                  {/* Deactivate */}
                  <button
                    disabled={u.id === me?.id}
                    onClick={() => handleDeactivate(u.id, u.is_active)}
                    title={u.is_active ? 'Deactivate account' : 'Activate account'}
                    className="p-2 rounded-lg text-gray-400 hover:bg-red-50 dark:hover:bg-red-900/20 hover:text-red-500 transition-colors disabled:opacity-30 disabled:cursor-not-allowed flex-shrink-0"
                  >
                    <UserX className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Layout>
  )
}
