import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { AuthProvider, useAuth } from './hooks/useAuth.jsx'
import { ThemeProvider } from './hooks/useTheme.jsx'
import AuthPage        from './pages/AuthPage.jsx'
import OAuthCallback   from './pages/OAuthCallback.jsx'
import UploadPage      from './pages/UploadPage.jsx'
import ResultPage      from './pages/ResultPage.jsx'
import AnalystDashboard from './pages/Dashboard.jsx'
import AnalystReports  from './pages/AnalystReports.jsx'
import AdminDashboard  from './pages/AdminDashboard.jsx'
import AdminUsers      from './pages/AdminUsers.jsx'
import AdminModels     from './pages/AdminModels.jsx'
import AdminConfig     from './pages/AdminConfig.jsx'
import AdminLogs       from './pages/AdminLogs.jsx'

function Loading() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
      <div className="w-8 h-8 border-2 border-gray-300 border-t-blue-500 rounded-full animate-spin" />
    </div>
  )
}

function PublicRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <Loading />
  if (user) {
    return <Navigate to={user.role === 'admin' ? '/admin/dashboard' : '/analyst/dashboard'} replace />
  }
  return children
}

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <Loading />
  return user ? children : <Navigate to="/auth" replace />
}

function AdminRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <Loading />
  if (!user) return <Navigate to="/auth" replace />
  if (user.role !== 'admin') {
    return <Navigate to="/analyst/dashboard" state={{ accessDenied: true }} replace />
  }
  return children
}

function AnalystRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <Loading />
  if (!user) return <Navigate to="/auth" replace />
  if (user.role === 'admin') return <Navigate to="/admin/dashboard" replace />
  return children
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <div className="grain-overlay" aria-hidden="true" />
        <Routes>
          {/* Root → role dashboard */}
          <Route path="/" element={<RootRedirect />} />

          {/* Public */}
          <Route path="/auth"          element={<PublicRoute><AuthPage /></PublicRoute>} />
          <Route path="/auth/callback" element={<OAuthCallback />} />

          {/* Legacy aliases */}
          <Route path="/dashboard" element={<Navigate to="/analyst/dashboard" replace />} />
          <Route path="/admin"     element={<Navigate to="/admin/dashboard"  replace />} />

          {/* Shared (any authenticated role) */}
          <Route path="/upload"             element={<ProtectedRoute><UploadPage /></ProtectedRoute>} />
          <Route path="/results/:dump_id"   element={<ProtectedRoute><ResultPage /></ProtectedRoute>} />

          {/* Forensic Analyst */}
          <Route path="/analyst/dashboard" element={<AnalystRoute><AnalystDashboard /></AnalystRoute>} />
          <Route path="/analyst/reports"   element={<AnalystRoute><AnalystReports /></AnalystRoute>} />

          {/* Admin */}
          <Route path="/admin/dashboard" element={<AdminRoute><AdminDashboard /></AdminRoute>} />
          <Route path="/admin/users"     element={<AdminRoute><AdminUsers /></AdminRoute>} />
          <Route path="/admin/models"    element={<AdminRoute><AdminModels /></AdminRoute>} />
          <Route path="/admin/config"    element={<AdminRoute><AdminConfig /></AdminRoute>} />
          <Route path="/admin/logs"      element={<AdminRoute><AdminLogs /></AdminRoute>} />

          {/* Catch-all */}
          <Route path="*" element={<RootRedirect />} />
        </Routes>
      </AuthProvider>
    </ThemeProvider>
  )
}

function RootRedirect() {
  const { user, loading } = useAuth()
  if (loading) return <Loading />
  if (!user) return <Navigate to="/auth" replace />
  return <Navigate to={user.role === 'admin' ? '/admin/dashboard' : '/analyst/dashboard'} replace />
}
