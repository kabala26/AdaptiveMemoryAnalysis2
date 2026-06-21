import { useState } from "react";
import LoginForm from "../components/LoginForm.jsx";
import RegisterForm from "../components/RegisterForm.jsx";
import OAuthButton from "../components/OAuthButton.jsx";
import { initiateOAuth } from "../utils/oauth.js";
import { Shield } from "lucide-react";
import ThemeToggle from "../components/ThemeToggle.jsx";

export default function AuthPage() {
  const [mode, setMode] = useState("login"); // 'login' | 'register'
  const [loadingProvider, setLP] = useState(null); // 'google' | 'github' | null

  function handleOAuth(provider) {
    setLP(provider);
    // Small delay so the spinner renders before the redirect
    setTimeout(() => initiateOAuth(provider), 120);
  }

  const isLogin = mode === "login";

  return (
    <div className="min-h-dvh flex flex-col items-center justify-center px-4 py-12 relative overflow-hidden">
      {/* Theme Toggle Button */}
      <div className="absolute top-4 right-4 z-10">
        <ThemeToggle />
      </div>

      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 overflow-hidden"
      >
        <div className="absolute -top-40 -right-40 w-[600px] h-[600px] rounded-full bg-gray-200 opacity-60 blur-3xl" />
        <div className="absolute -bottom-60 -left-20 w-[500px] h-[500px] rounded-full bg-gray-200 opacity-40 blur-3xl" />
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[800px] h-[1px] bg-gray-300 opacity-60" />
      </div>

      <div className="relative w-full max-w-[420px]">
        
        <div className="animate-fade-up flex flex-col items-center mb-8">
          <div className="w-12 h-12 rounded-2xl bg-gray-900 flex items-center justify-center mb-4 shadow-lg dark:bg-gray-100">
            <Shield className="w-6 h-6 text-white dark:text-gray-900" strokeWidth={1.5} />
          </div>
          <h1 className="font-display text-3xl text-gray-900 tracking-tight dark:text-white">
            {isLogin ? "Welcome back" : "Create account"}
          </h1>
          <p className="mt-1.5 text-sm text-gray-500 font-body font-light dark:text-gray-400">
            {isLogin
              ? "Sign in to your MemShield workspace"
              : "Start your forensic analysis journey"}
          </p>
        </div>

        {/* Main card */}
        <div className="animate-fade-up animation-delay-100 relative bg-white rounded-3xl shadow-[0_8px_40px_-12px_rgba(28,23,18,0.15)] border border-gray-200 overflow-hidden dark:bg-gray-800 dark:border-gray-700">
          {/* Top accent line */}
          <div className="h-[2px] w-full bg-gradient-to-r from-primary-400 via-primary-500 to-gray-900 dark:from-primary-400 dark:via-primary-500 dark:to-gray-100" />

          <div className="p-6 sm:p-8">
            <div className="space-y-3">
              <OAuthButton
                provider="google"
                loading={loadingProvider === "google"}
                disabled={!!loadingProvider}
                onClick={() => handleOAuth("google")}
              />
              <OAuthButton
                provider="github"
                loading={loadingProvider === "github"}
                disabled={!!loadingProvider}
                onClick={() => handleOAuth("github")}
              />
            </div>

            <div className="my-6 divider-text">
              <span>or continue with email</span>
            </div>

            {isLogin ? <LoginForm /> : <RegisterForm />}

            {/* Mode toggle */}
            <p className="mt-6 text-center text-sm text-gray-500 dark:text-gray-400">
              {isLogin
                ? "Don't have an account? "
                : "Already have an account? "}
              <button
                onClick={() => setMode(isLogin ? "register" : "login")}
                className="link-styled font-medium"
              >
                {isLogin ? "Sign up" : "Sign in"}
              </button>
            </p>
          </div>
        </div>

        {/* Bonus: Account linking notice */}
        <p className="animate-fade-up animation-delay-400 mt-3 text-center text-xs text-gray-300 italic">
          Same email across providers? We'll link your accounts automatically.
        </p>
      </div>
    </div>
  );
}
