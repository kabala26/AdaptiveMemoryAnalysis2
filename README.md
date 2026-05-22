# MemShield — Adaptive Memory Malware Analysis Platform

A full-stack forensic analysis platform that classifies Windows memory dumps as **Benign or Malware** using Volatility 3 feature extraction and a three-stage Random Forest pipeline. Malicious dumps are further classified into a **malware category** (Ransomware / Spyware / Trojan) and a specific **malware family** (Conti, Zeus, Emotet, and 12 others). The platform supports adaptive retraining: analyst-confirmed labels are accumulated in the database and folded into new model versions automatically every week.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Machine Learning Pipeline](#3-machine-learning-pipeline)
4. [Feature Extraction](#4-feature-extraction)
5. [Dataset](#5-dataset)
6. [Tech Stack](#6-tech-stack)
7. [Project Structure](#7-project-structure)
8. [Database Schema](#8-database-schema)
9. [REST API Reference](#9-rest-api-reference)
10. [Frontend Pages](#10-frontend-pages)
11. [Requirements & Setup](#11-requirements--setup)
12. [Running the Application](#12-running-the-application)
13. [Training the Models](#13-training-the-models)
14. [Environment Variables](#14-environment-variables)
15. [Role-Based Access Control](#15-role-based-access-control)
16. [Adaptive Retraining Workflow](#16-adaptive-retraining-workflow)
17. [Analysis Workflow (End-to-End)](#17-analysis-workflow-end-to-end)
18. [Running Tests](#18-running-tests)

---

## 1. Project Overview

MemShield is built as a final-year research project demonstrating the application of machine learning to Windows memory forensics. The core idea is to extract behavioural indicators from raw memory dumps using Volatility 3, represent them as a 55-element feature vector matching the **CICMalMem-2022** dataset schema, and classify them with a Random Forest model that achieves **99.99 % test accuracy** on held-out data.

Key capabilities:

| Capability | Detail |
|---|---|
| Binary classification | Benign vs. Malware (99.99 % accuracy) |
| Category classification | Ransomware / Spyware / Trojan (75.4 % accuracy) |
| Family classification | 15 specific families (52.7 % accuracy) |
| Two-phase extraction | Benign early-exit saves ~7 min per clean dump |
| CSV batch mode | Classifies every row in a CICMalMem-format CSV directly |
| Adaptive retraining | Weekly automatic retraining with analyst-confirmed labels |
| Ranked probabilities | Full probability distribution shown for every candidate family |
| Audit logging | Every user action is logged with IP, timestamp, and details |
| OAuth SSO | Google and GitHub sign-in alongside email/password |

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        Browser                          │
│  React 18 + Vite + Tailwind CSS + React Router 6        │
└────────────────────────┬────────────────────────────────┘
                         │  HTTP / JWT
┌────────────────────────▼────────────────────────────────┐
│                   Flask 3  (port 5000)                  │
│                                                         │
│  /api/auth/*        JWT auth, OAuth, RBAC               │
│  /api/analysis/*    Upload, analyse, results, admin     │
│                                                         │
│  Background threads:                                    │
│    _analysis_worker  — Volatility + RF classification   │
│    _retrain_worker   — adaptive model retraining        │
│    APScheduler       — weekly retrain cron              │
└──────────┬──────────────────────┬───────────────────────┘
           │                      │
┌──────────▼──────┐   ┌───────────▼──────────────────────┐
│  PostgreSQL 14  │   │          ML Modules               │
│                 │   │                                   │
│  users          │   │  modules/feature_extractor.py     │
│  memory_dumps   │   │    Volatility 3 plugin runner     │
│  features       │   │                                   │
│  results        │   │  modules/feature_mapper.py        │
│  ml_models      │   │    55-column vector builder       │
│  labeled_samples│   │                                   │
│  audit_logs     │   │  modules/classifier.py            │
└─────────────────┘   │    Binary RF (Benign/Malware)     │
                       │                                   │
                       │  modules/family_classifier.py     │
                       │    Category + Family RF           │
                       │                                   │
                       │  modules/model_trainer.py         │
                       │    Adaptive retrain pipeline      │
                       └───────────────────────────────────┘
```

---

## 3. Machine Learning Pipeline

Analysis runs in three sequential stages. Stages 2 and 3 only execute when Stage 1 returns `Malware`.

### Stage 1 — Binary Classifier

- **Algorithm**: RandomForestClassifier (100 trees, balanced class weights)
- **Input**: 55-element feature vector extracted from the memory dump
- **Output**: `Benign` or `Malware` + probability score
- **Test accuracy**: 99.99 %
- **Model file**: `models/rf_<timestamp>.joblib`

### Stage 2a — Category Classifier

- **Algorithm**: RandomForestClassifier (100 trees, balanced class weights)
- **Input**: Same 55 features, trained on **malicious samples only**
- **Output**: Ranked probability list for `Ransomware`, `Spyware`, `Trojan`
- **Test accuracy**: 75.4 %
- **Model file**: `models/category_classifier.joblib`

### Stage 2b — Family Classifier

- **Algorithm**: RandomForestClassifier (100 trees, balanced class weights)
- **Input**: Same 55 features, trained on malicious samples only
- **Output**: Ranked probability list for 15 malware families
- **Families**: Ako, Conti, Maze, REvil, Ryuk (Ransomware) · Agent Tesla, Lokibot, Formbook, Remcos, Raccoon (Spyware) · Emotet, TrickBot, Zeus, Gator, Tofsee (Trojan)
- **Test accuracy**: 52.7 %
- **Model file**: `models/family_classifier.joblib`

### Two-Phase Extraction (Performance Optimisation)

Running all Volatility plugins on a clean dump wastes ~7 minutes because Malfind and SvcScan are slow. The platform solves this with a two-phase approach:

```
Phase 1 — Fast plugins (≤ 5 min timeout)
  PsList, PsScan, DllList, VadInfo, Handles
       │
       ▼
  Binary classify with fast features
       │
       ├─ Benign ≥ 80 % confidence? → COMPLETE (skip Phase 2)
       │
       └─ Otherwise ↓
       
Phase 2 — Full extraction (≤ 10 min total timeout)
  All Phase 1 plugins + Malfind + SvcScan
       │
       ▼
  Re-classify with full 55-feature vector
       │
       ▼
  Stage 2 family classification (if Malware)
```

### CSV Batch Mode

When the uploaded file has a `.csv` extension the platform skips Volatility entirely. It detects whether the file matches the CICMalMem-2022 column schema (requires at least half of the 55 feature columns to be present), builds the feature matrix, and classifies every row. The result page shows:

- Stat tiles: Total / Benign / Malware count / Detection rate
- Category breakdown bar chart
- All detected families with counts and percentages

---

## 4. Feature Extraction

The `FeatureExtractor` class in `modules/feature_extractor.py` runs Volatility 3 plugins against the raw dump file and returns a structured dictionary. The `feature_mapper.py` module converts that dictionary to the canonical 55-column vector.

| Plugin group | Features | Count |
|---|---|---|
| `windows.pslist` + `windows.psscan` | Process count, parent PIDs, threads, 64-bit procs, handlers | 5 |
| `windows.dlllist` | DLL count, avg DLLs per process | 2 |
| `windows.handles` | Handle counts by type (port, file, event, desktop, key, thread, dir, semaphore, timer, section, mutant) | 13 |
| `windows.ldrmodules` | Hidden modules (not in Load / Init / Mem lists) | 6 |
| `windows.malfind` | Injection count, commit charge, protection flags, unique injections | 4 |
| `windows.psxview` | Process hiding indicators (DKOM, pool, thread, CSRSS, session, desktop) | 14 |
| `windows.modules` | Loaded kernel modules | 1 |
| `windows.svcscan` | Service counts by type (kernel/FS drivers, process services, active) | 7 |
| `windows.callbacks` | Kernel callbacks (total, anonymous, generic) | 3 |
| **Total** | | **55** |

Per-plugin timeouts are set to 180 seconds to prevent stalled Volatility processes from blocking the worker thread indefinitely.

---

## 5. Dataset

**CICMalMem-2022** (Obfuscated-MalMem2022.csv) — published by the Canadian Institute for Cybersecurity.

| Attribute | Value |
|---|---|
| Total samples | 58,596 |
| Benign samples | ~20,000 |
| Malware samples | ~38,596 |
| Malware categories | 3 (Ransomware, Spyware, Trojan) |
| Malware families | 15 |
| Features per row | 55 (extracted by Volatility 3) |
| Target column | `Class` (Benign / Malware) |
| Category column | `Category` — encodes `<Type>-<Family>-<sha256>-<N>.raw` |

The dataset CSV must be placed at `dataset/Obfuscated-MalMem2022.csv`. The `dataset/` directory is excluded from git (see `.gitignore`).

Download: [https://www.unb.ca/cic/datasets/malmem-2022.html](https://www.unb.ca/cic/datasets/malmem-2022.html)

---

## 6. Tech Stack

### Backend

| Package | Version | Purpose |
|---|---|---|
| Flask | 3.0.3 | Web framework |
| Flask-SQLAlchemy | 3.1.1 | ORM |
| Flask-JWT-Extended | 4.6.0 | JWT authentication |
| Flask-CORS | 4.0.1 | CORS headers |
| psycopg2-binary | 2.9.12 | PostgreSQL adapter |
| bcrypt | 4.1.3 | Password hashing |
| APScheduler | 3.x | Weekly retrain cron |
| scikit-learn | ≥ 1.5.0 | Random Forest models |
| numpy | ≥ 2.2.0 | Feature vectors |
| pandas | ≥ 2.3.0 | CSV loading |
| joblib | ≥ 1.4.0 | Model serialisation |
| volatility3 | 2.28.0 | Memory dump analysis |
| pefile | 2024.8.26 | PE header parsing |
| gunicorn | 22.0.0 | Production WSGI server |

### Frontend

| Package | Version | Purpose |
|---|---|---|
| React | 18.2 | UI framework |
| React Router | 6.20 | Client-side routing |
| Vite | 5.0 | Build tool |
| Tailwind CSS | 3.3 | Utility CSS |
| Axios | 1.6 | HTTP client |
| TanStack Table | 8.21 | Sortable data tables |
| Lucide React | 0.383 | Icon set |
| Redux Toolkit | 2.11 | Auth state management |

---

## 7. Project Structure

```
AdaptiveMemoryAnalysis2/
│
├── run.py                          # Flask entry point
│
├── backend/
│   ├── __init__.py                 # App factory, extensions, APScheduler
│   ├── models/
│   │   ├── user.py                 # User model (OAuth + email/password)
│   │   └── analysis.py            # MemoryDump, AnalysisFeatures, AnalysisResult,
│   │                               #   MlModel, LabeledSample, AuditLog
│   ├── routes/
│   │   ├── auth.py                 # Auth endpoints (register, login, OAuth, users)
│   │   └── analysis.py            # Analysis endpoints (upload, analyse, results, admin)
│   ├── utils/
│   │   ├── roles.py                # Role decorators (require_role)
│   │   └── oauth.py                # Google / GitHub OAuth helpers
│   ├── migrations/                 # SQL migration scripts (reference)
│   └── requirements.txt
│
├── modules/
│   ├── classifier.py              # Binary RF training script
│   ├── family_classifier.py       # Category + family RF training & inference
│   ├── feature_extractor.py       # Volatility 3 plugin runner
│   ├── feature_mapper.py          # 55-column vector builder
│   └── model_trainer.py           # Adaptive retrain pipeline
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx                 # Routes + auth guards
│   │   ├── components/
│   │   │   ├── Layout.jsx          # Sidebar navigation
│   │   │   ├── LoginForm.jsx
│   │   │   ├── RegisterForm.jsx
│   │   │   ├── OAuthButton.jsx
│   │   │   ├── ThemeToggle.jsx
│   │   │   └── SessionTimeoutModal.jsx
│   │   ├── pages/
│   │   │   ├── AuthPage.jsx        # Login + registration
│   │   │   ├── OAuthCallback.jsx   # OAuth redirect handler
│   │   │   ├── UploadPage.jsx      # Dump upload
│   │   │   ├── ResultPage.jsx      # Analysis result + family rankings
│   │   │   ├── Dashboard.jsx       # Analyst dashboard
│   │   │   ├── AnalystReports.jsx  # Analyst's own uploads
│   │   │   ├── AdminDashboard.jsx  # Admin overview + all dumps
│   │   │   ├── AdminUsers.jsx      # User management
│   │   │   ├── AdminModels.jsx     # Model versions
│   │   │   ├── AdminLabeledSamples.jsx  # Ground-truth labels
│   │   │   ├── AdminConfig.jsx     # System configuration
│   │   │   └── AdminLogs.jsx       # Audit logs
│   │   ├── hooks/
│   │   │   ├── useAuth.jsx
│   │   │   ├── useTheme.jsx
│   │   │   └── useToast.jsx
│   │   └── utils/
│   │       ├── api.js              # Axios instance with JWT interceptor
│   │       ├── oauth.js
│   │       └── validation.js
│   ├── package.json
│   ├── vite.config.js
│   └── tailwind.config.js
│
├── models/                        # Saved .joblib model files (git-ignored)
│   ├── rf_<timestamp>.joblib
│   ├── category_classifier.joblib
│   └── family_classifier.joblib
│
├── dataset/                       # CICMalMem-2022 CSV (git-ignored)
│   └── Obfuscated-MalMem2022.csv
│
├── uploads/                       # Raw dump files (git-ignored, auto-deleted post-analysis)
├── tests/                         # pytest test suite
└── .env                           # Environment variables (never commit)
```

---

## 8. Database Schema

Six tables are created automatically by SQLAlchemy on startup.

### `users`
| Column | Type | Notes |
|---|---|---|
| id | VARCHAR(36) PK | UUID |
| email | VARCHAR(254) UNIQUE | |
| name | VARCHAR(255) | |
| profile_picture | TEXT | OAuth avatar URL |
| password_hash | VARCHAR(255) | NULL for OAuth-only users |
| oauth_provider | VARCHAR(32) | `google` / `github` / `email` |
| oauth_provider_id | VARCHAR(255) | |
| role | VARCHAR(32) | `admin` / `forensic_analyst` |
| is_active | BOOLEAN | Soft-disable flag |
| created_at / updated_at / last_login_at | TIMESTAMPTZ | |

### `memory_dumps`
| Column | Type | Notes |
|---|---|---|
| dump_id | VARCHAR(36) PK | UUID |
| user_id | FK → users | CASCADE delete |
| file_path / file_name / file_size / hash_value | | |
| status | VARCHAR(32) | `pending` / `processing` / `complete` / `failed` |
| upload_date | TIMESTAMPTZ | |

### `features`
| Column | Type | Notes |
|---|---|---|
| feature_id | PK | |
| dump_id | FK → memory_dumps | CASCADE delete, UNIQUE |
| process_count / dll_count | INTEGER | Summary stats |
| feature_data | JSON | Full extraction output |

### `results`
| Column | Type | Notes |
|---|---|---|
| result_id | PK | |
| dump_id | FK → memory_dumps | CASCADE delete |
| model_id | FK → ml_models | RESTRICT delete |
| prediction | VARCHAR(32) | `Benign` / `Malware` |
| confidence | FLOAT | |
| malware_category | VARCHAR(64) | `Ransomware` / `Spyware` / `Trojan` |
| category_confidence | FLOAT | |
| malware_family | VARCHAR(64) | e.g. `Conti`, `Zeus` |
| family_confidence | FLOAT | |
| classification_date | TIMESTAMPTZ | |

### `ml_models`
| Column | Type | Notes |
|---|---|---|
| model_id | PK | |
| model_name / algorithm / accuracy | | |
| model_path | TEXT | Path to `.joblib` file |
| feature_importance | JSON | Top feature importances |
| training_date | TIMESTAMPTZ | |
| activated_at | TIMESTAMPTZ | NULL = not yet active |

### `labeled_samples`
| Column | Type | Notes |
|---|---|---|
| sample_id | PK | |
| dump_id | FK → memory_dumps | SET NULL on delete |
| feature_vector | JSON | 55-element float list |
| true_label | VARCHAR(32) | `Benign` / `Malware` |
| source | VARCHAR(64) | `manual` / `confirmed_prediction` |
| added_by | FK → users | |
| included_in_model_id | FK → ml_models | NULL = pending retrain |
### `audit_logs`
| Column | Type | Notes |
|---|---|---|
| log_id | PK | |
| user_id | FK → users | SET NULL on delete |
| action | VARCHAR(64) | e.g. `upload`, `analyze`, `retrain` |
| resource_type / resource_id | | |
| ip_address | VARCHAR(45) | IPv4 or IPv6 |
| timestamp | TIMESTAMPTZ | |
| details | JSON | Action-specific metadata |

---

## 9. REST API Reference

All endpoints are prefixed with `/api`. Protected endpoints require a `Bearer <access_token>` header.

### Auth — `/api/auth`

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/register` | — | Create an account (email + password) |
| POST | `/login` | — | Login; returns `access_token` + `refresh_token` |
| POST | `/logout` | JWT | Invalidate refresh token |
| POST | `/refresh` | Refresh token | Issue new access token |
| GET | `/me` | JWT | Current user profile |
| GET | `/users` | Admin | List all users |
| POST | `/users/<id>/role` | Admin | Change a user's role |
| POST | `/users/<id>/deactivate` | Admin | Toggle a user's active status |
| GET | `/oauth/google` | — | Redirect to Google OAuth |
| GET | `/oauth/github` | — | Redirect to GitHub OAuth |
| GET | `/oauth/google/callback` | — | Google OAuth callback |
| GET | `/oauth/github/callback` | — | GitHub OAuth callback |

### Analysis — `/api/analysis`

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/upload` | JWT | Upload a memory dump or CSV file |
| POST | `/analyze` | JWT | Trigger analysis on an uploaded dump |
| GET | `/results/<dump_id>` | JWT | Poll analysis status and fetch results |
| GET | `/dumps` | JWT | List dumps (own for analysts, all for admins) |
| GET | `/stats` | Admin | System-wide stats (total, detection rate, disk) |
| GET | `/models` | Admin | List all trained model versions |
| POST | `/models/<id>/activate` | Admin | Set a model as the active production model |
| POST | `/retrain` | Admin | Trigger adaptive retraining immediately |
| DELETE | `/dumps/<dump_id>` | Admin | Permanently delete a dump and its records |
| POST | `/cleanup` | Admin | Delete all raw dump files from disk |
| GET | `/logs` | Admin | Paginated audit log (`?page=&per_page=&action=&user_id=`) |
| GET | `/labeled-samples` | Admin | List ground-truth labeled samples |
| POST | `/labeled-samples` | Admin | Add a labeled sample for future retraining |

#### Result object (GET `/results/<dump_id>`)

```json
{
  "dump_id": "...",
  "file_name": "win10.raw",
  "status": "complete",
  "prediction": "Malware",
  "confidence": 0.94,
  "malware_category": "Ransomware",
  "category_confidence": 0.91,
  "malware_family": "Conti",
  "family_confidence": 0.87,
  "category_rankings": [
    { "category": "Ransomware", "confidence": 0.91 },
    { "category": "Trojan",     "confidence": 0.06 }
  ],
  "family_rankings": [
    { "family": "Conti", "confidence": 0.87 },
    { "family": "MAZE",  "confidence": 0.07 }
  ],
  "suspicious_artifacts": [...],
  "feature_importance": [...],
  "dump_feature_values": [...],
  "is_batch": false,
  "batch_summary": null
}
```

---

## 10. Frontend Pages

| Route | Role | Description |
|---|---|---|
| `/auth` | Public | Login, registration, Google/GitHub OAuth |
| `/upload` | All | Upload memory dumps (.raw, .mem, .dmp, .vmem) or CICMalMem CSV |
| `/results/:id` | All | Live-polling result page; shows family probability bars for malicious dumps, batch summary table for CSV uploads |
| `/analyst/dashboard` | Analyst | Personal analysis summary |
| `/analyst/reports` | Analyst | Own upload history and results |
| `/admin/dashboard` | Admin | System overview, all-users dump table with delete action |
| `/admin/users` | Admin | User list with role selector and activate/deactivate toggle |
| `/admin/models` | Admin | Model version history, activate / export feature-importance CSV |
| `/admin/samples` | Admin | Ground-truth labeled samples, add labels, view pending count |
| `/admin/config` | Admin | System configuration (confidence threshold, max upload size, toggles) |
| `/admin/logs` | Admin | Paginated audit log with action-type filter and CSV export |

---

## 11. Requirements & Setup

### System prerequisites

| Dependency | Minimum version | Notes |
|---|---|---|
| Python | 3.10 | 3.13 recommended for scikit-learn wheel availability |
| Node.js | 18 | LTS preferred |
| PostgreSQL | 14 | |
| Volatility 3 | 2.28 | Installed via pip in the Python venv |

### 1. Clone the repository

```bash
git clone https://github.com/kabala26/AdaptiveMemoryAnalysis2.git
cd AdaptiveMemoryAnalysis2
```

### 2. Create a Python virtual environment

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r backend/requirements.txt
```

> **Important**: Always use the project venv when training models. The Flask server uses the same venv, so model files must be serialised with the same scikit-learn version.

### 3. Configure environment variables

Copy `.env.example` to `.env` (or create `.env` manually):

```bash
cp .env.example .env
```

See [Section 14 — Environment Variables](#14-environment-variables) for all required keys.

### 4. Create the PostgreSQL database

```bash
psql -U postgres -c "CREATE DATABASE main_auth;"
```

The schema is created automatically by SQLAlchemy when the Flask app starts for the first time. Reference SQL is in `backend/migrations/schema.sql`.

### 5. Place the dataset

Download **Obfuscated-MalMem2022.csv** from the CIC website and place it at:

```
dataset/Obfuscated-MalMem2022.csv
```

### 6. Train the initial models

```bash
# Binary classifier
source venv/bin/activate
python -m modules.classifier

# Category + family classifiers (requires the CSV)
python -m modules.family_classifier
```

This creates:

```
models/rf_<timestamp>.joblib
models/rf_<timestamp>_metadata.json
models/category_classifier.joblib
models/family_classifier.joblib
```

### 7. Install frontend dependencies

```bash
cd frontend
npm install
```

---

## 12. Running the Application

### Development

Open two terminals:

```bash
# Terminal 1 — Flask backend (port 5000)
source venv/bin/activate
python run.py

# Terminal 2 — Vite dev server (port 3000)
cd frontend
npm run dev
```

Browse to `http://localhost:3000`.

### Production build

```bash
# Build frontend assets
cd frontend && npm run build

# Serve backend with Gunicorn (adjust workers as needed)
cd ..
source venv/bin/activate
gunicorn -w 4 -b 0.0.0.0:5000 run:app
```

The built frontend assets in `frontend/dist/` can be served by Nginx. A sample `frontend/nginx.conf` is included in the repository.

---

## 13. Training the Models

### Binary classifier (manual retrain)

```bash
source venv/bin/activate
python -m modules.classifier
```

Or trigger from the Admin → Model Management page (runs `modules/model_trainer.py` in a background thread).

### Category + family classifiers

```bash
source venv/bin/activate
python -m modules.family_classifier
```

Or they retrain automatically whenever the admin triggers or the scheduler triggers an adaptive retrain.

### Re-running after adding labeled samples

From the Admin → Model Management page click **Retrain Model**. The pipeline in `modules/model_trainer.py` will:

1. Load the base CICMalMem-2022 dataset
2. Append all pending `labeled_samples` rows not yet included in a model
3. Train new binary, category, and family classifiers
4. Activate the new binary model if test accuracy ≥ current production accuracy
5. Record the outcome in `audit_logs`

---

## 14. Environment Variables

Create a `.env` file in the project root with the following keys:

```dotenv
# Flask
SECRET_KEY=<random-string-32-chars>

# JWT
JWT_SECRET_KEY=<different-random-string>
JWT_ACCESS_EXPIRES_SECONDS=900       # 15 minutes (default)
JWT_REFRESH_EXPIRES_SECONDS=604800   # 7 days (default)

# Database
DATABASE_URL=postgresql://postgres:<password>@localhost:5432/main_auth

# URLs
FRONTEND_URL=http://localhost:3000
BACKEND_URL=http://localhost:5000

# Google OAuth
GOOGLE_CLIENT_ID=<your-google-client-id>
GOOGLE_CLIENT_SECRET=<your-google-client-secret>

# GitHub OAuth
GITHUB_CLIENT_ID=<your-github-client-id>
GITHUB_CLIENT_SECRET=<your-github-client-secret>

# Optional
UPLOAD_FOLDER=uploads               # default: <project_root>/uploads
```

#### Generating secrets

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

#### OAuth setup

**Google**: Create credentials in [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials. Authorised redirect URI: `http://localhost:5000/api/auth/oauth/google/callback`.

**GitHub**: Register an OAuth App in GitHub Settings → Developer settings. Callback URL: `http://localhost:5000/api/auth/oauth/github/callback`.

---

## 15. Role-Based Access Control

Two roles are supported:

| Role | Permissions |
|---|---|
| `admin` | Full access — all API endpoints, all users' dumps, model management, audit logs, user deactivation |
| `forensic_analyst` | Upload dumps, trigger analysis, view **own** results only |

Roles are enforced server-side by the `@require_role(...)` decorator on every protected route. A forensic analyst who requests another user's result receives a 403 error.

The first account registered in a fresh database should be manually promoted to admin:

```sql
UPDATE users SET role = 'admin' WHERE email = 'your@email.com';
```

---

## 16. Adaptive Retraining Workflow

```
┌───────────────────────────────────────────┐
│  Analyst reviews a result in the UI       │
│  → Confirms / corrects the label          │
└──────────────────┬────────────────────────┘
                   │ POST /api/analysis/labeled-samples
                   ▼
┌───────────────────────────────────────────┐
│  LabeledSample row saved in DB            │
│  feature_vector = 55-element float list   │
│  true_label     = "Benign" | "Malware"    │
│  included_in_model_id = NULL (pending)    │
└──────────────────┬────────────────────────┘
                   │
          APScheduler fires weekly
          (or admin clicks Retrain)
                   │
                   ▼
┌───────────────────────────────────────────┐
│  modules/model_trainer._retrain()         │
│                                           │
│  1. Load base CSV (58,596 rows)           │
│  2. Append pending LabeledSample rows     │
│  3. Train binary RF on combined dataset   │
│  4. Train category + family RFs           │
│  5. Evaluate on held-out test split       │
│  6. If new_acc ≥ current_acc → activate   │
│  7. Mark all pending samples as consumed  │
│  8. Write AuditLog entry                  │
└───────────────────────────────────────────┘
```

Only one retraining job can run at a time (`_retrain_lock` mutex prevents concurrent runs).

---

## 17. Analysis Workflow (End-to-End)

```
User uploads file
       │
       ├─ .csv extension?
       │     └─ CSV batch mode:
       │          - Validate CICMalMem column schema
       │          - Classify all rows directly (no Volatility)
       │          - Return aggregated family / category stats
       │
       └─ Memory dump (.raw / .mem / .dmp / .vmem):
             │
             ▼
      Phase 1 — Fast Volatility plugins (≤ 5 min)
      PsList · PsScan · DllList · VadInfo · Handles
             │
             ▼
      Binary classify with fast features
             │
             ├─ Benign ≥ 80 %?
             │     └─ Save features + result → COMPLETE
             │
             └─ Otherwise:
                   │
                   ▼
            Phase 2 — Full extraction (≤ 10 min total)
            + Malfind · SvcScan
                   │
                   ▼
            Re-classify with full 55-feature vector
                   │
                   ├─ Benign → Save → COMPLETE
                   │
                   └─ Malware:
                         ▼
                   Stage 2 — Family Classification
                   Category RF → Ransomware / Spyware / Trojan
                   Family RF  → Conti / Zeus / Emotet / …
                         │
                         ▼
                   Save to DB → Delete raw file → COMPLETE
```

The frontend polls `GET /api/analysis/results/<dump_id>` every 3 seconds until `status === "complete"` or `"failed"`.

---

## 18. Running Tests

```bash
source venv/bin/activate
pytest tests/ -v
```

Test files:

| File | What it covers |
|---|---|
| `tests/test_classifier.py` | Binary RF training and prediction |
| `tests/test_feature_extractor.py` | FeatureExtractor plugin output structure |
| `tests/test_feature_mapper.py` | 55-column vector mapping correctness |
| `tests/test_analysis_api.py` | Upload, analyze, results API endpoints |
| `tests/test_classification_inference.py` | End-to-end classification inference |
| `tests/test_model_trainer.py` | Adaptive retraining pipeline |

> Tests that require Volatility to run against a real memory dump are skipped automatically when no dump file is available. Tests against the binary classifier require the dataset CSV and the trained model files.

---

## Licence

This project is developed for academic research and educational purposes.
