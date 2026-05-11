# AdaptiveMemoryAnalysis2 — CLAUDE.md

## Project Overview

**Adaptive ML-Based Malware Classification from Volatile Memory** — a final-year computer science project. The system accepts raw memory dumps from Windows machines, extracts forensic features via the Volatility Framework, and classifies them as benign or malicious using a trained Random Forest model. A full-stack web application wraps this pipeline with role-based access (analysts upload dumps; admins manage users and retrain models).

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  React Frontend  (Vite + Tailwind CSS)  — port 3000              │
│  Auth page · Analyst dashboard · Admin dashboard                 │
└───────────────────────┬──────────────────────────────────────────┘
                        │  REST / JWT (axios + auto-refresh)
┌───────────────────────▼──────────────────────────────────────────┐
│  Flask Backend  (Python 3.x)  — port 5000                        │
│  Auth blueprint · Analysis blueprint (to be built)               │
│  SQLAlchemy ORM  ←→  PostgreSQL  (auth/user data)                │
│  ML pipeline     ←→  SQLite       (analysis jobs & results)      │
└───────────────────────┬──────────────────────────────────────────┘
                        │
          ┌─────────────▼──────────────┐
          │  Volatility 3 Framework    │
          │  Memory feature extraction │
          └─────────────┬──────────────┘
                        │
          ┌─────────────▼──────────────┐
          │  Random Forest Classifier  │
          │  Trained on CICMalMem-2022 │
          └────────────────────────────┘
```

---

## Technology Stack

### Backend — `backend/`
| Concern | Technology |
|---------|-----------|
| Language | Python 3.x |
| Web framework | Flask 3.0 |
| ORM | Flask-SQLAlchemy 3.1 |
| Auth database | PostgreSQL (psycopg2-binary) |
| Analysis database | SQLite (lightweight, local, per-deployment) |
| Authentication | Flask-JWT-Extended 4.6 (access 15 min / refresh 7 days) |
| Password hashing | bcrypt (12 rounds) |
| OAuth | Google OAuth 2.0, GitHub OAuth 2.0 |
| CORS | Flask-CORS (restricted to `FRONTEND_URL`) |
| Memory forensics | Volatility 3 Framework |
| ML classifier | scikit-learn — Random Forest |
| Training dataset | CICMalMem-2022 |
| WSGI server (prod) | gunicorn |

### Frontend — `frontend/`
| Concern | Technology |
|---------|-----------|
| Runtime | Node.js / npm |
| Framework | React 18 |
| Build tool | Vite 5 |
| Styling | Tailwind CSS 3 (class-based dark mode) |
| Routing | React Router v6 |
| HTTP client | axios (with JWT interceptor + auto-refresh) |
| State management | React Context (`useAuth`, `useTheme`) + Redux Toolkit |
| Table | TanStack React Table v8 |
| Icons | Lucide React |
| Fonts | Playfair Display (display), DM Sans (body), DM Mono (mono) |

---

## What Is Already Built

### Authentication system (complete)
- Email/password register + login with bcrypt hashing
- Google OAuth 2.0 and GitHub OAuth 2.0 flows with CSRF state tokens
- Account linking: same email across providers merges into one record
- JWT access + refresh tokens; auto-refresh on 401 in the frontend axios client
- Timing-safe login (constant-time bcrypt even for unknown emails)
- Role-based access control: `admin` | `analyst` roles embedded in JWT claims

### Frontend shell (complete)
- Auth page with login/register forms and OAuth buttons
- Analyst dashboard: stat cards, forensic artifact results table, memory dump upload zone (`.raw`, `.mem`, `.vmem`)
- Admin dashboard: user list with inline role assignment, system stats
- Dark/light theme toggle (persisted in localStorage, respects system preference)
- Role-aware routing: admins redirect to `/admin`, analysts to `/dashboard`

### Database schema (complete)
- `users` table in PostgreSQL — see `backend/migrations/schema.sql`
- RBAC `role` column added via `backend/migrations/add_role_column.sql`

---

## What Needs To Be Built

### ML / forensics pipeline
1. **Volatility integration** — Flask route accepts uploaded memory dump, runs Volatility 3 plugins (e.g. `windows.pslist`, `windows.malfind`, `windows.netscan`) and extracts feature vectors
2. **Feature engineering** — map Volatility output to the feature schema used in CICMalMem-2022
3. **Random Forest model** — train on CICMalMem-2022 dataset, persist with `joblib`, expose a `/api/analysis/predict` endpoint
4. **Analysis jobs table** — SQLite schema to store upload metadata, extracted features, verdict, and timestamps
5. **Results wiring** — replace sample data in `Dashboard.jsx` with real API calls to `/api/analysis/history`

### Production hardening (post-MVP)
- JWT blocklist (Redis) for true logout and refresh token rotation
- Replace in-process OAuth state store (`backend/utils/oauth.py`) with Redis TTL keys
- Rate limiting (flask-limiter) on `/api/auth/login` and `/api/auth/register`
- Serve tokens via fragment (`#`) or short-lived server code instead of query string to avoid log exposure

---

## Directory Structure

```
AdaptiveMemoryAnalysis2/
├── backend/
│   ├── __init__.py              # App factory: Flask, SQLAlchemy, JWT, CORS
│   ├── models/
│   │   └── user.py              # User model (OAuth + email/password unified)
│   ├── routes/
│   │   └── auth.py              # All auth endpoints (/api/auth/*)
│   ├── utils/
│   │   └── oauth.py             # OAuth state management + provider exchange
│   ├── migrations/
│   │   ├── schema.sql           # Reference PostgreSQL schema
│   │   ├── add_role_column.sql  # RBAC migration
│   │   └── migrate.py           # Migration runner script
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # Routes + ProtectedRoute + RoleProtectedRoute
│   │   ├── main.jsx             # React entry point
│   │   ├── index.css            # Tailwind + custom component classes
│   │   ├── components/
│   │   │   ├── LoginForm.jsx
│   │   │   ├── RegisterForm.jsx
│   │   │   ├── OAuthButton.jsx
│   │   │   └── ThemeToggle.jsx
│   │   ├── hooks/
│   │   │   ├── useAuth.jsx      # AuthContext: user, login, logout, loading
│   │   │   └── useTheme.jsx     # ThemeContext: theme, toggleTheme, isDark
│   │   ├── pages/
│   │   │   ├── AuthPage.jsx     # Login/register + OAuth buttons
│   │   │   ├── Dashboard.jsx    # Analyst view (upload zone + results table)
│   │   │   ├── AdminDashboard.jsx # Admin view (user management)
│   │   │   └── OAuthCallback.jsx  # Receives tokens from OAuth redirect
│   │   └── utils/
│   │       ├── api.js           # axios instance with JWT interceptor + auto-refresh
│   │       ├── oauth.js         # Client-side OAuth state generation + redirect
│   │       └── validation.js    # Form validation helpers
│   ├── index.html
│   ├── package.json
│   └── tailwind.config.js
├── .env                         # Secret keys, DB URL, OAuth credentials (git-ignored)
├── .gitignore
└── CLAUDE.md
```

---

## Running Locally

### Backend
```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
# Ensure PostgreSQL is running and .env is populated
flask --app __init__:create_app run --debug --port 5000
```

### Frontend
```bash
cd frontend
npm install
npm run dev          # starts on http://localhost:3000
```

### Environment variables (`.env`)
```
SECRET_KEY=...
DATABASE_URL=postgresql://user:pass@localhost:5432/main_auth
JWT_SECRET_KEY=...
JWT_ACCESS_EXPIRES_SECONDS=900
JWT_REFRESH_EXPIRES_SECONDS=604800
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
FRONTEND_URL=http://localhost:3000
BACKEND_URL=http://localhost:5000
```

---

## API Reference

All endpoints are under `/api/auth/`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/register` | — | Create email/password account |
| POST | `/login` | — | Login, returns `access_token` + `refresh_token` + `user` |
| POST | `/refresh` | refresh JWT | Get new access token |
| POST | `/logout` | access JWT | Invalidate session (client clears tokens) |
| GET | `/me` | access JWT | Current user profile |
| GET | `/google` | — | Redirect to Google consent |
| GET | `/google/callback` | — | Handle Google OAuth code exchange |
| GET | `/github` | — | Redirect to GitHub consent |
| GET | `/github/callback` | — | Handle GitHub OAuth code exchange |
| GET | `/users` | admin JWT | List all users |
| POST | `/users/<id>/role` | admin JWT | Assign `admin` or `analyst` role |

---

## Dataset & Model Notes

**CICMalMem-2022** (Canadian Institute for Cybersecurity):
- Memory dump samples labelled benign and malicious (ransomware, spyware, trojan)
- Features extracted from Volatility plugin outputs (process lists, network connections, injected code regions, etc.)
- Random Forest chosen for: interpretability, resistance to overfitting on tabular forensic features, fast inference, and feature-importance output useful for a dissertation

The trained model (`model.pkl` / `model.joblib`) should be placed in `backend/ml/` once trained. The analysis pipeline (upload → Volatility → feature vector → predict → store) is the primary remaining implementation work.
