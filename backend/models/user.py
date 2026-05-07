"""
User model — stores both OAuth and email/password users.

Columns
-------
id                  UUID primary key
email               Unique, indexed
name                Display name
profile_picture     URL from OAuth provider (nullable for email users)
password_hash       bcrypt hash (nullable for OAuth-only users)
oauth_provider      'google' | 'github' | 'email'
oauth_provider_id   Provider-specific user ID (nullable for email users)
is_active           Soft disable flag
created_at          Row creation timestamp
updated_at          Auto-updated on change
last_login_at       Set on every successful authentication

Account linking
---------------
Users with the same verified email are treated as the same account.
If a user registers with email and later signs in with Google (same email),
we attach the OAuth provider ID to the existing record instead of
creating a duplicate — see the upsert_oauth_user helper.
"""

import uuid
from datetime import datetime, timezone
import bcrypt
from .. import db


class User(db.Model):
    __tablename__ = 'users'

    # ── Identity ──────────────────────────────────────────────────
    id      = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email   = db.Column(db.String(254), unique=True, nullable=False, index=True)
    name    = db.Column(db.String(255), nullable=False)

    # ── Profile ───────────────────────────────────────────────────
    profile_picture = db.Column(db.Text, nullable=True)

    # ── Auth ──────────────────────────────────────────────────────
    password_hash     = db.Column(db.String(255), nullable=True)   # null for OAuth-only
    oauth_provider    = db.Column(db.String(32),  nullable=True)   # google | github | email
    oauth_provider_id = db.Column(db.String(255), nullable=True)   # provider UID

    # ── Flags / timestamps ────────────────────────────────────────
    is_active     = db.Column(db.Boolean, default=True, nullable=False)
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                              onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)

    # ── Unique constraint: one provider ID per provider ───────────
    __table_args__ = (
        db.UniqueConstraint('oauth_provider', 'oauth_provider_id',
                            name='uq_oauth_provider_user'),
    )

    # ── Password helpers ──────────────────────────────────────────

    def set_password(self, plaintext: str) -> None:
        """Hash and store password using bcrypt."""
        self.password_hash = bcrypt.hashpw(
            plaintext.encode('utf-8'), bcrypt.gensalt(rounds=12)
        ).decode('utf-8')

    def check_password(self, plaintext: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        if not self.password_hash:
            return False
        return bcrypt.checkpw(plaintext.encode('utf-8'),
                               self.password_hash.encode('utf-8'))

    # ── Serialisation ─────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Safe public representation — never includes password_hash."""
        return {
            'id':              self.id,
            'email':           self.email,
            'name':            self.name,
            'profile_picture': self.profile_picture,
            'oauth_provider':  self.oauth_provider,
            'is_active':       self.is_active,
            'created_at':      self.created_at.isoformat(),
            'last_login_at':   self.last_login_at.isoformat() if self.last_login_at else None,
        }

    def touch_login(self) -> None:
        """Update last_login_at to now."""
        self.last_login_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return f'<User {self.email} [{self.oauth_provider}]>'
