# MemShield Auth

A production-quality OAuth 2.0 authentication system with Google and GitHub social login, email/password fallback, JWT session management, and account linking.

```
Frontend: React + Vite + Tailwind CSS + Lucide React
Backend:  Flask + SQLAlchemy + JWT Extended
Database: PostgreSQL
```

---

## ✦ Features

### Core (Required)
- **OAuth 2.0** — Google and GitHub social login with brand-accurate buttons
- **Email/Password** — Registration and login with server + client validation
- **JWT sessions** — Short-lived access tokens (15 min) + long-lived refresh tokens (7 days)
- **CSRF protection** — `state` parameter generated and validated on both frontend and backend
- **PostgreSQL** — Users stored with `email`, `name`, `profile_picture`, `oauth_provider_id`
- **Env-based secrets** — All Client IDs/Secrets loaded from `.env` via `python-dotenv`
- **Loading states** — Spinners on OAuth buttons during redirect; animated callback screen
- **Terms of Service** — Disclaimer with ToS and Privacy Policy links

### Bonus (Added)
- **Refresh Token flow** — Axios interceptor auto-refreshes expired access tokens silently
- **Account linking** — Same email from different providers merges into one user record (no duplicates)
- **Password strength indicator** — Live visual feedback during registration
- **Timing-safe login** — Dummy bcrypt call prevents email enumeration via response timing
- **Input sanitization** — Client and server-side validation with clear, specific error messages
- **Show/hide password** — Toggle visibility on all password fields
- **Accessible forms** — `aria-invalid`, `aria-describedby`, `role="alert"` throughout
- **Protected routes** — React Router guards for authenticated and unauthenticated pages
- **Dashboard** — Post-login page showing user profile and session status
- **Docker Compose** — One-command local stack (PostgreSQL + Flask + React)

---

## ✦ File Structure

```
auth-project/
├── frontend/                   # React + Vite application
│   ├── src/
│   │   ├── components/
│   │   │   ├── OAuthButton.jsx     # Google + GitHub brand buttons
│   │   │   ├── LoginForm.jsx       # Email/password login with validation
│   │   │   └── RegisterForm.jsx    # Registration with password strength meter
│   │   ├── hooks/
│   │   │   └── useAuth.jsx         # Auth context + token persistence
│   │   ├── pages/
│   │   │   ├── AuthPage.jsx        # Main auth card (OAuth + email toggle)
│   │   │   ├── OAuthCallback.jsx   # Handles OAuth redirect back
│   │   │   └── Dashboard.jsx       # Protected post-login page
│   │   ├── utils/
│   │   │   ├── api.js              # Axios instance + auto-refresh interceptor
│   │   │   ├── oauth.js            # State generation + validation + redirect
│   │   │   └── validation.js       # Client-side form validation rules
│   │   ├── App.jsx                 # Router + AuthProvider + route guards
│   │   ├── main.jsx
│   │   └── index.css               # Tailwind + custom component classes
│   ├── index.html
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── package.json
│
├── backend/                    # Flask Python application
│   ├── models/
│   │   └── user.py             # SQLAlchemy User model + bcrypt helpers
│   ├── routes/
│   │   └── auth.py             # All auth endpoints (OAuth + email + JWT)
│   ├── utils/
│   │   └── oauth.py            # Provider URL builders + token exchange
│   ├── migrations/
│   │   └── schema.sql          # Reference PostgreSQL schema
│   ├── __init__.py             # Flask app factory
│   └── requirements.txt
│
├── run.py                      # Flask entry point
├── .env.example                # Environment variable template
├── docker-compose.yml          # Full local stack
├── Dockerfile.backend
└── README.md
```

---

## ✦ Quick Start

### Option A: Docker Compose (recommended)

```bash
# 1. Clone and enter directory
git clone <repo> && cd auth-project

# 2. Copy and fill environment file
cp .env.example .env
# Edit .env — add your Google and GitHub OAuth credentials

# 3. Start everything
docker-compose up --build

# App runs at:
#   Frontend → http://localhost:3000
#   Backend  → http://localhost:5000
```

### Option B: Manual Setup

**Database**
```bash
createdb memshield_auth
# Or use docker: docker run -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
```

**Backend**
```bash
cd auth-project
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r backend/requirements.txt
cp .env.example .env   # Fill in your credentials
python run.py
# Flask runs on http://localhost:5000
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
# Vite runs on http://localhost:3000
```

---

## ✦ OAuth App Setup

### Google
1. Go to [Google Cloud Console → Credentials](https://console.cloud.google.com/apis/credentials)
2. Create **OAuth 2.0 Client ID** → Application type: **Web application**
3. Add Authorized redirect URI: `http://localhost:5000/api/auth/google/callback`
4. Copy Client ID and Secret into `.env`

### GitHub
1. Go to [GitHub Developer Settings](https://github.com/settings/developers) → **OAuth Apps** → **New OAuth App**
2. Set Authorization callback URL: `http://localhost:5000/api/auth/github/callback`
3. Copy Client ID and generate + copy Client Secret into `.env`

---

## ✦ API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`  | `/api/auth/google` | — | Redirect to Google consent |
| `GET`  | `/api/auth/google/callback` | — | Handle Google redirect |
| `GET`  | `/api/auth/github` | — | Redirect to GitHub consent |
| `GET`  | `/api/auth/github/callback` | — | Handle GitHub redirect |
| `POST` | `/api/auth/register` | — | Email/password registration |
| `POST` | `/api/auth/login` | — | Email/password login |
| `POST` | `/api/auth/refresh` | Refresh JWT | Issue new access token |
| `POST` | `/api/auth/logout` | Access JWT | Logout (client clears tokens) |
| `GET`  | `/api/auth/me` | Access JWT | Current user profile |

---

## ✦ Database Schema

```sql
CREATE TABLE users (
    id                  VARCHAR(36)   PRIMARY KEY,      -- UUID
    email               VARCHAR(254)  NOT NULL UNIQUE,
    name                VARCHAR(255)  NOT NULL,
    profile_picture     TEXT,                           -- OAuth avatar URL
    password_hash       VARCHAR(255),                   -- NULL for OAuth-only
    oauth_provider      VARCHAR(32),                    -- 'google'|'github'|'email'
    oauth_provider_id   VARCHAR(255),                   -- Provider UID
    is_active           BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_login_at       TIMESTAMPTZ,
    CONSTRAINT uq_oauth_provider_user UNIQUE (oauth_provider, oauth_provider_id)
);
```

---

## ✦ Security Notes

| Concern | Implementation |
|---------|---------------|
| CSRF | `state` parameter: generated with `crypto.getRandomValues()` (frontend) and `secrets.token_urlsafe()` (backend), stored in `sessionStorage` and validated on callback |
| Password storage | `bcrypt` with cost factor 12 |
| Token expiry | Access: 15 min · Refresh: 7 days |
| Email enumeration | Timing-safe login path (dummy bcrypt call for unknown emails) |
| XSS | React escapes all rendered values; JWT stored in memory (not `localStorage`) |
| Account linking | Same-email accounts from different providers merge automatically |
| Secrets | All credentials in `.env`, never committed |

### Production Hardening Checklist
- [ ] Add a **JWT blocklist** (Redis) for refresh token revocation on logout
- [ ] Add **rate limiting** (`flask-limiter`) on login/register/refresh endpoints  
- [ ] Use **PKCE** for OAuth flows instead of plain `state`  
- [ ] Serve over **HTTPS** only; set `Secure` and `HttpOnly` cookie flags if switching to cookie-based tokens  
- [ ] Add **CORS** origin whitelist (already configured, update for prod domain)  
- [ ] Replace in-process OAuth state store with **Redis** (TTL: 5 min)  
- [ ] Add **email verification** flow for email/password registrations  

---

## ✦ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend framework | React 18 + Vite 5 |
| Styling | Tailwind CSS 3 |
| Icons | Lucide React |
| HTTP client | Axios (with interceptor for silent refresh) |
| Routing | React Router v6 |
| Backend framework | Flask 3 |
| ORM | Flask-SQLAlchemy |
| Authentication | Flask-JWT-Extended |
| Password hashing | bcrypt |
| Database | PostgreSQL 16 |
| Containerization | Docker + Docker Compose |

---

*Built for Group 13 · MemShield · University of Dodoma · 2025/2026*
