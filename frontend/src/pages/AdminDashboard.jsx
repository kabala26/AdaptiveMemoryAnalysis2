import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth.jsx'
import ThemeToggle from '../components/ThemeToggle.jsx'
import api from '../utils/api.js'
import { LogOut, Shield, Users, BarChart3, Settings, UserPlus, Edit, Trash2 } from 'lucide-react'

export default function AdminDashboard() {
  const { user, logout } = useAuth()
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [showUserModal, setShowUserModal] = useState(false)
  const [selectedUser, setSelectedUser] = useState(null)

  const handleLogout = async () => {
    await logout()
    window.location.href = '/auth'
  }

  const fetchUsers = async () => {
    try {
      const response = await api.get('/auth/users')
      setUsers(response.data.users)
    } catch (error) {
      console.error('Failed to fetch users:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleRoleChange = async (userId, newRole) => {
    try {
      await api.post(`/auth/users/${userId}/role`, { role: newRole })
      fetchUsers() // Refresh user list
    } catch (error) {
      console.error('Failed to update role:', error)
    }
  }

  useEffect(() => {
    fetchUsers()
  }, [])

  if (!user) return null

  const stats = [
    { label: 'Total Users', value: users.length.toString(), icon: Users },
    { label: 'Admin Users', value: users.filter(u => u.role === 'admin').length.toString(), icon: Shield },
    { label: 'Analysts', value: users.filter(u => u.role === 'analyst').length.toString(), icon: BarChart3 },
  ]

  return (
    <div className="min-h-screen bg-gray-50 text-gray-900 font-sans light dark:bg-gray-900 dark:text-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 shadow-sm dark:bg-gray-800 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-ember-600 flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" strokeWidth={1.5} />
            </div>
            <div>
              <span className="font-display text-xl text-gray-900 dark:text-gray-50">MemShield Admin</span>
              <p className="text-xs text-gray-400 font-mono dark:text-gray-400">Administrator Panel</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <ThemeToggle />
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-ember-600 text-white hover:bg-ember-500 transition-colors font-body text-sm"
            >
              <LogOut className="w-4 h-4" />
              Logout
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Welcome Section */}
        <div className="mb-8">
          <h1 className="font-display text-3xl text-gray-900 mb-2 dark:text-gray-50">
            Welcome, {user?.name}
          </h1>
          <p className="text-gray-500 font-body dark:text-gray-400">
            Administrator dashboard for system management and monitoring
          </p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {stats.map((stat) => {
            const Icon = stat.icon
            return (
              <div
                key={stat.label}
                className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6 hover:shadow-md transition-shadow dark:bg-gray-800 dark:border-gray-700"
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="w-12 h-12 rounded-xl bg-blue-100 bg-opacity-50 flex items-center justify-center dark:bg-blue-900/20">
                    <Icon className="w-6 h-6 text-blue-600 dark:text-blue-400" />
                  </div>
                </div>
                <p className="text-xs font-mono text-gray-400 tracking-wide uppercase mb-2 dark:text-gray-400">
                  {stat.label}
                </p>
                <p className="font-display text-2xl text-gray-900 dark:text-gray-50">{stat.value}</p>
              </div>
            )
          })}
        </div>

        {/* Admin Actions */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* User Management */}
          <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-center gap-3 mb-4">
              <Users className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              <h2 className="font-display text-lg text-gray-900 dark:text-gray-50">User Management</h2>
            </div>
            <p className="text-sm text-gray-500 font-body mb-4 dark:text-gray-400">
              Manage users, assign roles, and control access permissions
            </p>
            
            {loading ? (
              <div className="text-center py-4">
                <div className="text-sm text-gray-500 dark:text-gray-400">Loading users...</div>
              </div>
            ) : (
              <div className="space-y-3">
                {users.map((u) => (
                  <div key={u.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg dark:bg-gray-700">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center text-xs font-medium text-gray-700 dark:bg-gray-600 dark:text-gray-200">
                        {u.name.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-900 dark:text-gray-50">{u.name}</p>
                        <p className="text-xs text-gray-500 dark:text-gray-400">{u.email}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <select
                        value={u.role}
                        onChange={(e) => handleRoleChange(u.id, e.target.value)}
                        className="text-xs px-2 py-1 rounded border border-gray-300 bg-white text-gray-700 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-200"
                        disabled={u.id === user.id}
                      >
                        <option value="analyst">Analyst</option>
                        <option value="admin">Admin</option>
                      </select>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* System Settings */}
          <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6 dark:bg-gray-800 dark:border-gray-700">
            <div className="flex items-center gap-3 mb-4">
              <Settings className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              <h2 className="font-display text-lg text-gray-900 dark:text-gray-50">System Settings</h2>
            </div>
            <p className="text-sm text-gray-500 font-body mb-4 dark:text-gray-400">
              Configure system parameters and security policies
            </p>
            <button className="w-full py-2 px-4 rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors font-body text-sm font-medium">
              System Configuration
            </button>
          </div>
        </div>

        {/* User Profile Info */}
        <div className="mt-8 bg-white rounded-2xl border border-gray-200 shadow-sm p-6 dark:bg-gray-800 dark:border-gray-700">
          <h3 className="font-display text-lg text-gray-900 mb-4 dark:text-gray-50">Your Admin Profile</h3>
          <div className="space-y-2">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              <span className="font-medium text-gray-900 dark:text-gray-50">Email:</span> {user?.email}
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              <span className="font-medium text-gray-900 dark:text-gray-50">Role:</span> <span className="inline-block px-2 py-1 rounded bg-blue-100 text-blue-600 text-xs font-mono font-medium dark:bg-blue-900/20 dark:text-blue-400">admin</span>
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              <span className="font-medium text-gray-900 dark:text-gray-50">Provider:</span> {user?.oauth_provider || 'email'}
            </p>
          </div>
        </div>
      </main>
    </div>
  )
}
