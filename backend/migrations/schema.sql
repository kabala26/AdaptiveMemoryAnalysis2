-- ============================================================
-- MemShield Auth — PostgreSQL Schema
-- Generated: 2026-05-06
--
-- This schema is created automatically by SQLAlchemy on startup
-- (db.create_all()). This file is provided for reference and
-- for manual migrations / documentation.
-- ============================================================

-- Enable pgcrypto for UUID generation (optional — we use Python UUIDs)
-- CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    -- Identity
    id                  VARCHAR(36)     PRIMARY KEY,
    email               VARCHAR(254)    NOT NULL UNIQUE,
    name                VARCHAR(255)    NOT NULL,

    -- Profile
    profile_picture     TEXT,

    -- Auth
    password_hash       VARCHAR(255),               -- NULL for OAuth-only users
    oauth_provider      VARCHAR(32),                -- 'google' | 'github' | 'email'
    oauth_provider_id   VARCHAR(255),               -- Provider-specific UID

    -- Flags & timestamps
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_login_at       TIMESTAMPTZ,

    -- Constraints
    CONSTRAINT uq_oauth_provider_user UNIQUE (oauth_provider, oauth_provider_id)
);

-- Index for email lookups (already covered by UNIQUE, added for clarity)
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- Auto-update updated_at trigger
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_set_updated_at ON users;
CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ── Sample rows (development only, remove in production) ─────────
-- INSERT INTO users (id, email, name, oauth_provider, is_active)
-- VALUES (gen_random_uuid()::text, 'test@example.com', 'Test User', 'email', TRUE);
