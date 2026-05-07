import { Shield, LogOut, User, Clock } from "lucide-react";
import { useAuth } from "../hooks/useAuth.jsx";

export default function Dashboard() {
  const { user, logout } = useAuth();

  const providerLabel = {
    google: "Google",
    github: "GitHub",
    email: "Email / Password",
  };

  return (
    <div className="min-h-dvh flex flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-md animate-fade-up">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-ink-950 flex items-center justify-center">
              <Shield
                className="w-[18px] h-[18px] text-cream"
                strokeWidth={1.5}
              />
            </div>
            <span className="font-display text-lg text-ink-950">MemShield</span>
          </div>
          <button
            onClick={logout}
            className="flex items-center gap-1.5 text-sm text-ink-500 hover:text-ink-800 transition-colors font-body"
            aria-label="Sign out"
          >
            <LogOut className="w-4 h-4" />
            Sign out
          </button>
        </div>

        {/* Welcome card */}
        <div className="bg-white rounded-3xl border border-ink-100 shadow-[0_8px_40px_-12px_rgba(28,23,18,0.12)] overflow-hidden">
          <div className="h-[2px] w-full " />
          <div className="p-8">
            {/* Avatar */}
            <div className="flex items-center gap-4 mb-6">
              {user?.profile_picture ? (
                <img
                  src={user.profile_picture}
                  alt={user.name}
                  className="w-14 h-14 rounded-2xl object-cover border border-ink-100"
                />
              ) : (
                <div className="w-14 h-14 rounded-2xl bg-parchment border border-ink-100 flex items-center justify-center">
                  <User className="w-7 h-7 text-ink-400" />
                </div>
              )}
              <div>
                <h2 className="font-display text-xl text-ink-950">
                  {user?.name || "Welcome"}
                </h2>
                <p className="text-sm text-ink-400 font-light">{user?.email}</p>
              </div>
            </div>

            {/* Details */}
            <div className="space-y-3">
              <div className="flex items-center justify-between py-3 border-b border-ink-100">
                <span className="text-xs font-mono text-ink-400 tracking-wide uppercase">
                  Signed in via
                </span>
                <span className="text-sm font-medium text-ink-700">
                  {providerLabel[user?.oauth_provider] || "Email"}
                </span>
              </div>
              <div className="flex items-center justify-between py-3">
                <span className="text-xs font-mono text-ink-400 tracking-wide uppercase">
                  Session
                </span>
                <span className="flex items-center gap-1.5 text-sm text-green-600 font-medium">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500 inline-block animate-pulse" />
                  Active
                </span>
              </div>
            </div>

            <p className="mt-6 text-sm text-ink-400 font-light text-center italic">
              Authentication successful. Your session is secured with JWT.
            </p>
          </div>
        </div>

        <p className="mt-4 text-center text-xs text-ink-300 font-mono">
          Token refreshes automatically · 15 min access / 7 day refresh
        </p>
      </div>
    </div>
  );
}
