import { useState } from "react";
import LoginForm from "../components/LoginForm.jsx";
import RegisterForm from "../components/RegisterForm.jsx";
import OAuthButton from "../components/OAuthButton.jsx";
import { initiateOAuth } from "../utils/oauth.js";
import { Shield } from "lucide-react";

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
      {/* Decorative background blobs */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 overflow-hidden"
      >
        <div className="absolute -top-40 -right-40 w-[600px] h-[600px] rounded-full bg-parchment opacity-60 blur-3xl" />
        <div className="absolute -bottom-60 -left-20 w-[500px] h-[500px] rounded-full bg-parchment opacity-40 blur-3xl" />
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[800px] h-[1px] bg-ink-200 opacity-60" />
      </div>

      {/* Card */}
      <div className="relative w-full max-w-[420px]">
        {/* Logo / brand mark */}
        <div className="animate-fade-up flex flex-col items-center mb-8">
          <div className="w-12 h-12 rounded-2xl bg-ink-950 flex items-center justify-center mb-4 shadow-lg">
            <Shield className="w-6 h-6 text-cream" strokeWidth={1.5} />
          </div>
          <h1 className="font-display text-3xl text-ink-950 tracking-tight">
            {isLogin ? "Welcome back" : "Create account"}
          </h1>
          <p className="mt-1.5 text-sm text-ink-500 font-body font-light">
            {isLogin
              ? "Sign in to your MemShield workspace"
              : "Start your forensic analysis journey"}
          </p>
        </div>

        {/* Main card */}
        <div className="animate-fade-up animation-delay-100 relative bg-white rounded-3xl shadow-[0_8px_40px_-12px_rgba(28,23,18,0.15)] border border-ink-100 overflow-hidden">
          {/* Top accent line */}
          <div className="h-[2px] w-full " />

          <div className="p-8">
            {/* OAuth Buttons */}
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

            {/* Divider */}
            <div className="my-6 divider-text">
              <span>or continue with email</span>
            </div>

            {/* Email / password form */}
            {isLogin ? <LoginForm /> : <RegisterForm />}

            {/* Mode toggle */}
            <p className="mt-6 text-center text-sm text-ink-500">
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

        {/* Terms */}
        <p className="animate-fade-up animation-delay-300 mt-6 text-center text-xs text-ink-400 leading-relaxed px-4">
          By continuing, you agree to our{" "}
          <a href="/terms" className="link-styled">
            Terms of Service
          </a>{" "}
          and{" "}
          <a href="/privacy" className="link-styled">
            Privacy Policy
          </a>
          . We handle your data with care.
        </p>

        {/* Bonus: Account linking notice */}
        <p className="animate-fade-up animation-delay-400 mt-3 text-center text-xs text-ink-300 italic">
          Same email across providers? We'll link your accounts automatically.
        </p>
      </div>
    </div>
  );
}
