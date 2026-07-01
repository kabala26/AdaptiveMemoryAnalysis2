import { useState, useEffect } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  Shield, LayoutDashboard, FileUp, FileText,
  Users, Cpu, Settings, ShieldAlert, Search, LogOut, Tag, Menu, X,
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
  { label: 'Dashboard',       icon: LayoutDashboard, href: '/admin/dashboard' },
  { label: 'Upload',          icon: FileUp,           href: '/upload' },
  { label: 'All Analyses',    icon: Search,           href: '/admin/dashboard' },
  { label: 'Users',           icon: Users,            href: '/admin/users' },
  { label: 'Training & Models', icon: Cpu,            href: '/admin/models' },
  { label: 'Labeled Samples', icon: Tag,              href: '/admin/samples' },
  { label: 'Config',          icon: Settings,         href: '/admin/config' },
  { label: 'Logs',            icon: ShieldAlert,      href: '/admin/logs' },
]

export default function Layout({ children }) {
  const { user, logout } = useAuth()
  const location = useLocation()
  const navigate  = useNavigate()
  const [open, setOpen] = useState(false)

  const isAdmin = user?.role === 'admin'
  const links   = isAdmin ? ADMIN_LINKS : ANALYST_LINKS

  const accent = isAdmin
    ? { text: 'text-navy-700 dark:text-navy-300', activeBg: 'bg-navy-50 dark:bg-navy-900/30', badge: 'bg-navy-100 text-navy-700 dark:bg-navy-800/60 dark:text-navy-200' }
    : { text: 'text-blue-600 dark:text-blue-400', activeBg: 'bg-blue-50 dark:bg-blue-900/20', badge: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' }

  const roleName   = isAdmin ? 'Administrator' : 'Forensic Analyst'
  const avatarSeed = encodeURIComponent(user?.email || user?.name || 'user')
  const avatarUrl  = `https://api.dicebear.com/9.x/identicon/svg?seed=${avatarSeed}`

  // Close drawer on route change
  useEffect(() => { setOpen(false) }, [location.pathname])

  // Prevent body scroll when drawer is open on mobile
  useEffect(() => {
    document.body.style.overflow = open ? 'hidden' : ''
    return () => { document.body.style.overflow = '' }
  }, [open])

  async function handleLogout() {
    await logout()
    navigate('/auth')
  }

  const SidebarContent = () => (
    <>
      {/* Logo */}
      <div className="p-5 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-gray-900 dark:bg-gray-100 rounded-xl flex items-center justify-center shadow-md flex-shrink-0">
            <Shield className="w-5 h-5 text-white dark:text-gray-900" strokeWidth={1.5} />
          </div>
          <div>
            <span className="font-display text-base text-gray-900 dark:text-white tracking-tight leading-none">MemShield</span>
            <span className={`block text-[9px] font-mono tracking-widest uppercase mt-0.5 ${accent.text}`}>{roleName}</span>
          </div>
        </div>
        {/* Close button — mobile only */}
        <button
          onClick={() => setOpen(false)}
          className="lg:hidden p-1.5 rounded-lg text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
          aria-label="Close menu"
        >
          <X className="w-5 h-5" />
        </button>
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
          <img
            src={avatarUrl}
            alt={user?.name || 'User avatar'}
            className="w-8 h-8 rounded-lg flex-shrink-0 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700"
          />
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
    </>
  )

  return (
    <div className="flex min-h-screen bg-[#F1F5F9] dark:bg-gray-900 text-gray-900 dark:text-gray-50">

      {/* ── Desktop sidebar (always visible ≥ lg) ── */}
      <aside className="hidden lg:flex w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 flex-col fixed h-full z-30">
        <SidebarContent />
      </aside>

      {/* ── Mobile drawer backdrop ── */}
      {open && (
        <div
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm lg:hidden"
          onClick={() => setOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* ── Mobile drawer ── */}
      <aside className={`
        fixed top-0 left-0 h-full w-72 max-w-[85vw] z-50
        bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700
        flex flex-col
        transform transition-transform duration-300 ease-in-out
        lg:hidden
        ${open ? 'translate-x-0' : '-translate-x-full'}
      `}>
        <SidebarContent />
      </aside>

      {/* ── Main content area ── */}
      <div className="flex-1 min-w-0 lg:ml-64 flex flex-col min-h-screen">

        {/* ── Mobile top bar ── */}
        <header className="lg:hidden sticky top-0 z-30 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-4 h-14 flex items-center gap-3 shadow-sm">
          <button
            onClick={() => setOpen(true)}
            className="p-2 rounded-lg text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            aria-label="Open menu"
          >
            <Menu className="w-5 h-5" />
          </button>
          <div className="flex items-center gap-2.5 flex-1">
            <div className="w-7 h-7 bg-gray-900 dark:bg-gray-100 rounded-lg flex items-center justify-center shadow-sm">
              <Shield className="w-4 h-4 text-white dark:text-gray-900" strokeWidth={1.5} />
            </div>
            <span className="font-display text-sm text-gray-900 dark:text-white tracking-tight">MemShield</span>
          </div>
          <ThemeToggle />
        </header>

        <main className="flex-1 min-w-0 p-4 sm:p-6 lg:p-8">
          {children}
        </main>
      </div>

      <SessionTimeoutModal />
    </div>
  )
}
