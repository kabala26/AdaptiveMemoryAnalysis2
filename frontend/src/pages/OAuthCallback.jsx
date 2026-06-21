import { useEffect, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Shield, AlertCircle } from "lucide-react";
import { useAuth } from "../hooks/useAuth.jsx";
import api from "../utils/api.js";
import { useState } from "react";

export default function OAuthCallback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { login } = useAuth();
  const [error, setError] = useState(null);
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;

    // 1. Grab the TOKENS the backend just handed you
    const accessToken = searchParams.get("access_token");
    const refreshToken = searchParams.get("refresh_token");

    // 3. Use the tokens immediately
    if (accessToken && refreshToken) {
      // We fetch the user profile just to verify the token is active
      api
        .get("/auth/me", {
          headers: { Authorization: `Bearer ${accessToken}` },
        })
        .then(({ data }) => {
          login(
            { access_token: accessToken, refresh_token: refreshToken },
            data.user,
          );
          // Navigate based on role
          const dashboard = data.user.role === 'admin' ? '/admin/dashboard' : '/analyst/dashboard';
          navigate(dashboard, { replace: true });
        })
        .catch(() => {
          setError("Session verification failed. Please try again.");
        });
    } else {
      setError("Authentication tokens were not received from the server.");
    }
  }, []);

  if (error) {
    return (
      <div className="min-h-dvh flex items-center justify-center px-4 bg-[#F1F5F9] dark:bg-gray-900">
        <div className="text-center max-w-sm">
          <div className="w-12 h-12 rounded-2xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 flex items-center justify-center mx-auto mb-4">
            <AlertCircle className="w-6 h-6 text-red-500" />
          </div>
          <h2 className="font-display text-xl text-gray-900 dark:text-white mb-2">
            Authentication failed
          </h2>
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">{error}</p>
          <button
            onClick={() => navigate("/auth", { replace: true })}
            className="px-5 py-2.5 rounded-xl bg-navy-700 hover:bg-navy-600 text-white text-sm font-medium transition-colors"
          >
            Back to sign in
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      className="min-h-dvh flex flex-col items-center justify-center px-4 bg-[#F1F5F9] dark:bg-gray-900"
      aria-live="polite"
      aria-label="Completing sign in"
    >
      <div className="flex flex-col items-center gap-5">
        <div className="relative">
          <div className="w-14 h-14 rounded-2xl bg-gray-900 dark:bg-gray-100 flex items-center justify-center shadow-md">
            <Shield className="w-7 h-7 text-white dark:text-gray-900" strokeWidth={1.5} />
          </div>
          <div className="absolute inset-0 rounded-2xl border-2 border-gray-400 animate-ping opacity-40" />
        </div>
        <div className="text-center">
          <p className="font-display text-lg text-gray-900 dark:text-white">
            Completing sign in…
          </p>
          <p className="text-sm text-gray-400 dark:text-gray-500 mt-1 font-light">
            Hang tight, securing your session
          </p>
        </div>
        {/* Animated dots */}
        <div className="flex gap-1.5" aria-hidden="true">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className="w-2 h-2 rounded-full bg-gray-300 dark:bg-gray-600 animate-bounce"
              style={{ animationDelay: `${i * 150}ms` }}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
