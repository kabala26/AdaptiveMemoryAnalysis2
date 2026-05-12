import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  Shield, LayoutDashboard, FileUp, FileText,
  Users, Cpu, Settings, ShieldAlert, Search, LogOut,
} from 'lucide-react'
import { useAuth } from '../hooks/useAuth.jsx'
import ThemeToggle from './ThemeToggle.jsx'
import SessionTimeoutModal from './SessionTimeoutModal.jsx'

const ANALYST_LINKS = [
  { label: 'Dashboard',  icon: LayoutDashboard, href: '/analyst/dashboard' },
  { label: 'Upload',     icon: FileUp,           href: '/upload' },
  { label: 'My Reports', icon: FileText,         href: '/analyst/reports' },
]

const ADMIN_LINKS = [
  { label: 'Dashboard',     icon: LayoutDashboard, href: '/admin/dashboard' },
  { label: 'Upload',        icon: FileUp,           href: '/upload' },
  { label: 'All Analyses',  icon: Search,           href: '/admin/dashboard' },
  { label: 'Users',         icon: Users,            href: '/admin/users' },
  { label: 'Models',        icon: Cpu,              href: '/admin/models' },
  { label: 'Config',        icon: Settings,         href: '/admin/config' },
  { label: 'Logs',          icon: ShieldAlert,      href: '/admin/logs' },
]

export default function Layout({ children }) {
  const { user, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const isAdmin = user?.role === 'admin'
  const links   = isAdmin ? ADMIN_LINKS : ANALYST_LINKS

  // Accent palette
  const accent = isAdmin
    ? { bg: 'bg-amber-500', text: 'text-amber-600 dark:text-amber-400', activeBg: 'bg-amber-50 dark:bg-amber-900/20', badge: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300' }
    : { bg: 'bg-blue-600',  text: 'text-blue-600 dark:text-blue-400',   activeBg: 'bg-blue-50 dark:bg-blue-900/20',   badge: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' }

  const initials  = (user?.name || 'U').split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)
  const roleName  = isAdmin ? 'Administrator' : 'Forensic Analyst'

  async function handleLogout() {
    await logout()
    navigate('/auth')
  }

  return (
    <div className="flex min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-50">
      {/* ── Sidebar ── */}
      <aside className="w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 flex flex-col fixed h-full z-30">
        {/* Logo */}
        <div className="p-5 border-b border-gray-100 dark:border-gray-700">
          <div className="flex items-center gap-3">
            <div className={`w-9 h-9 ${accent.bg} rounded-xl flex items-center justify-center shadow-md`}>
              <Shield className="w-5 h-5 text-white" strokeWidth={1.5} />
            </div>
            <div>
              <span className="font-display text-base text-gray-900 dark:text-white tracking-tight leading-none">MemShield</span>
              <span className={`block text-[9px] font-mono tracking-widest uppercase mt-0.5 ${accent.text}`}>{roleName}</span>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-3 space-y-0.5 overflow-y-auto">
          {links.map(link => {
            const isActive = location.pathname === link.href
            return (
              <Link
                key={link.label}
                to={link.href}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all ${
                  isActive
                    ? `${accent.activeBg} ${accent.text} font-medium`
                    : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700/60'
                }`}
              >
                <link.icon className="w-4 h-4 flex-shrink-0" />
                {link.label}
              </Link>
            )
          })}
        </nav>

        {/* User footer */}
        <div className="p-3 border-t border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2.5 px-2.5 py-2 rounded-xl bg-gray-50 dark:bg-gray-700/50 mb-2">
            <div className={`w-8 h-8 rounded-lg ${accent.bg} flex items-center justify-center text-white text-xs font-bold flex-shrink-0`}>
              {initials}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 dark:text-white truncate leading-tight">{user?.name}</p>
              <span className={`inline-block text-[9px] font-mono px-1.5 py-0.5 rounded mt-0.5 ${accent.badge}`}>
                {user?.role}
              </span>
            </div>
          </div>
          <div className="flex gap-1.5">
            <ThemeToggle />
            <button
              onClick={handleLogout}
              className="flex-1 flex items-center justify-center gap-1.5 px-2 py-2 rounded-lg text-xs text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign Out
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main content ── */}
      <div className="flex-1 ml-64 flex flex-col min-h-screen">
        <main className="flex-1 p-8">
          {children}
        </main>
      </div>

      <SessionTimeoutModal />
    </div>
  )
}
