/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        display: ['"Playfair Display"', 'serif'],
        body:    ['"DM Sans"', 'sans-serif'],
        mono:    ['"DM Mono"', 'monospace'],
      },
      colors: {
        primary: {
          50: '#eff6ff', 100: '#dbeafe', 200: '#bfdbfe', 300: '#93c5fd',
          400: '#60a5fa', 500: '#3b82f6', 600: '#2563eb', 700: '#1d4ed8',
          800: '#1e40af', 900: '#1e3a8a', 950: '#172554',
        },
        amber: {
          50: '#fffbeb', 100: '#fef3c7', 200: '#fde68a', 300: '#fcd34d',
          400: '#fbbf24', 500: '#f59e0b', 600: '#d97706', 700: '#b45309',
          800: '#92400e', 900: '#78350f', 950: '#451a03',
        },
        // Admin accent — derived from the project's Security Color Palette
        // (navy #1d3353, cream #eee4bd, sky #64a9ee, slate #727ea5, clay #a5744d)
        navy: {
          50: '#eef2f8', 100: '#d8e1ee', 200: '#b3c5dd', 300: '#87a2c5',
          400: '#5d7da8', 500: '#3f5f87', 600: '#2c4868', 700: '#1d3353',
          800: '#152740', 900: '#0f1c2e', 950: '#080f1a',
        },
        clay: {
          50: '#faf4ef', 100: '#f0e0d2', 200: '#e1c1a6', 300: '#cfa07c',
          400: '#bb8763', 500: '#a5744d', 600: '#8a5f3e', 700: '#6e4b32',
          800: '#523825', 900: '#3a271a',
        },
        gray: {
          50: '#f9fafb', 100: '#f3f4f6', 200: '#e5e7eb', 300: '#d1d5db',
          400: '#9ca3af', 500: '#6b7280', 600: '#4b5563', 700: '#374151',
          800: '#1f2937', 900: '#111827', 950: '#030712',
        },
      },
      keyframes: {
        fadeUp: {
          '0%':   { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideIn: {
          '0%':   { opacity: '0', transform: 'translateX(1.5rem)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        spin: {
          to: { transform: 'rotate(360deg)' },
        },
      },
      animation: {
        'fade-up':  'fadeUp 0.6s ease-out forwards',
        'slide-in': 'slideIn 0.2s ease-out',
        spin:       'spin 1s linear infinite',
      },
    },
  },
  plugins: [],
}
