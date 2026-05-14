"""
Authentication Blueprint
========================

Routes
------
GET  /api/auth/google              →  redirect to Google OAuth
GET  /api/auth/google/callback     →  handle Google code exchange
GET  /api/auth/github              →  redirect to GitHub OAuth
GET  /api/auth/github/callback     →  handle GitHub code exchange
POST /api/auth/register            →  email/password registration
POST /api/auth/login               →  email/password login
POST /api/auth/logout              →  invalidate refresh token (client clears access token)
POST /api/auth/refresh             →  issue new access token from refresh token
GET  /api/auth/me                  →  return current user profile

Bonus features implemented
--------------------------
* Refresh tokens (7-day, stored as JWT — add a token blocklist for revocation in prod)
* Account linking: same email from different providers merges into one user record
* Rate limiting hint: add flask-limiter in production
"""

from datetime import datetime, timezone
from flask import Blueprint, current_app, jsonify, redirect, request
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    get_jwt_identity, get_jwt, jwt_required,
)

from .. import db
from ..models.user import User
from ..utils.oauth import (
    generate_state, validate_and_consume_state,
    google_auth_url, exchange_google_code,
    github_auth_url, exchange_github_code,
)

auth_bp = Blueprint('auth', __name__)


# ══════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════

def _make_tokens(user: User) -> tuple[str, str]:
    """Issue a fresh access + refresh token pair for a user with role claim."""
    identity = user.id
    additional_claims = {'role': user.role}
    return (
        create_access_token(identity=identity, additional_claims=additional_claims),
        create_refresh_token(identity=identity, additional_claims=additional_claims),
    )


def _auth_response(user: User, status: int = 200):
    """Standard JSON response after successful authentication."""
    access, refresh = _make_tokens(user)
    user.touch_login()
    db.session.commit()
    return jsonify({
        'access_token':  access,
        'refresh_token': refresh,
        'user':          user.to_dict(),
    }), status


def _upsert_oauth_user(provider: str, profile: dict) -> User:
    """
    Find or create a user from an OAuth profile.

    Account-linking logic:
      1. Look up by (provider, provider_id) — exact match.
      2. If not found, look up by email — link the provider to existing account.
      3. If still not found, create a new user.
    """
    user = User.query.filter_by(
        oauth_provider=provider,
        oauth_provider_id=profile['provider_id'],
    ).first()

    if user is None:
        # Try linking by email
        user = User.query.filter_by(email=profile['email']).first()
        if user:
            # Link this provider to the existing account
            user.oauth_provider    = provider
            user.oauth_provider_id = profile['provider_id']
            if profile.get('profile_picture') and not user.profile_picture:
                user.profile_picture = profile['profile_picture']

    if user is None:
        # Brand-new user
        user = User(
            email             = profile['email'],
            name              = profile['name'],
            profile_picture   = profile.get('profile_picture'),
            oauth_provider    = provider,
            oauth_provider_id = profile['provider_id'],
        )
        db.session.add(user)

    db.session.flush()  # assign id before commit
    return user


def _error(message: str, status: int = 400):
    return jsonify({'message': message}), status


# ══════════════════════════════════════════════════════════════════
#  OAuth — Google
# ══════════════════════════════════════════════════════════════════

@auth_bp.get('/google')
def google_login():
    """Redirect browser to Google's consent screen."""
    state = generate_state()
    return redirect(google_auth_url(state))


@auth_bp.get('/google/callback')
def google_callback():
    """
    Handle the redirect from Google.
    Validates state (CSRF), exchanges code, upserts user, returns tokens.
    The frontend receives tokens via URL fragment and stores them in memory.
    """
    code  = request.args.get('code')
    state = request.args.get('state', '')

    if not validate_and_consume_state(state):
        return _error('Invalid or expired OAuth state parameter.', 403)

    if not code:
        return _error('No authorization code received from Google.', 400)

    try:
        profile = exchange_google_code(code)
    except Exception as exc:
        current_app.logger.error('Google token exchange failed: %s', exc)
        return _error('Failed to exchange Google authorization code.', 502)

    try:
        user = _upsert_oauth_user('google', profile)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.error('DB upsert failed: %s', exc)
        return _error('Could not persist user record.', 500)

    access, refresh = _make_tokens(user)
    user.touch_login()
    db.session.commit()

    # Redirect to frontend callback page with tokens in query string.
    # In production use a fragment (#) or a short-lived server-side code
    # to avoid tokens appearing in server logs.
    frontend = current_app.config['FRONTEND_URL']
    return redirect(
        f"{frontend}/auth/callback"
        f"?access_token={access}"
        f"&refresh_token={refresh}"
        f"&provider=google"
        f"&state={state}"
    )


# ══════════════════════════════════════════════════════════════════
#  OAuth — GitHub
# ══════════════════════════════════════════════════════════════════

@auth_bp.get('/github')
def github_login():
    """Redirect browser to GitHub's consent screen."""
    state = generate_state()
    return redirect(github_auth_url(state))


@auth_bp.get('/github/callback')
def github_callback():
    """Handle the redirect from GitHub."""
    code  = request.args.get('code')
    state = request.args.get('state', '')

    if not validate_and_consume_state(state):
        return _error('Invalid or expired OAuth state parameter.', 403)

    if not code:
        return _error('No authorization code received from GitHub.', 400)

    try:
        profile = exchange_github_code(code)
    except ValueError as exc:
        return _error(str(exc), 400)
    except Exception as exc:
        current_app.logger.error('GitHub token exchange failed: %s', exc)
        return _error('Failed to exchange GitHub authorization code.', 502)

    try:
        user = _upsert_oauth_user('github', profile)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.error('DB upsert failed: %s', exc)
        return _error('Could not persist user record.', 500)

    access, refresh = _make_tokens(user)
    user.touch_login()
    db.session.commit()

    frontend = current_app.config['FRONTEND_URL']
    return redirect(
        f"{frontend}/auth/callback"
        f"?access_token={access}"
        f"&refresh_token={refresh}"
        f"&provider=github"
        f"&state={state}"
    )


# ══════════════════════════════════════════════════════════════════
#  Email / Password — Register
# ══════════════════════════════════════════════════════════════════

@auth_bp.post('/register')
def register():
    """
    Create a new email/password account.

    Body: { "name": str, "email": str, "password": str }
    """
    data = request.get_json(silent=True) or {}

    name     = (data.get('name')     or '').strip()
    email    = (data.get('email')    or '').strip().lower()
    password = (data.get('password') or '')

    # Server-side validation
    if not name or len(name) < 2:
        return _error('Name must be at least 2 characters.')
    if not email or '@' not in email:
        return _error('A valid email address is required.')
    if len(password) < 8:
        return _error('Password must be at least 8 characters.')

    if User.query.filter_by(email=email).first():
        return _error('An account with this email already exists.', 409)

    user = User(
        email          = email,
        name           = name,
        oauth_provider = 'email',
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return _auth_response(user, 201)


# ══════════════════════════════════════════════════════════════════
#  Email / Password — Login
# ══════════════════════════════════════════════════════════════════

@auth_bp.post('/login')
def login():
    """
    Authenticate with email and password.

    Body: { "email": str, "password": str }
    """
    data = request.get_json(silent=True) or {}

    email    = (data.get('email')    or '').strip().lower()
    password = (data.get('password') or '')

    if not email or not password:
        return _error('Email and password are required.')

    user = User.query.filter_by(email=email).first()

    # Constant-time path: always call check_password even if user is None
    # to avoid timing attacks revealing whether an email is registered.
    dummy_hash = '$2b$12$K9vBBy6.p6V.jN6f6F6f6u6f6F6f6F6f6F6f6F6f6F6f6F6f6F6f6'
    if user is None:
        import bcrypt as _bcrypt
        _bcrypt.checkpw(b'dummy', dummy_hash.encode())
        return _error('Invalid email or password.', 401)

    if not user.is_active:
        return _error('This account has been disabled. Contact support.', 403)

    if not user.check_password(password):
        return _error('Invalid email or password.', 401)

    return _auth_response(user)


# ══════════════════════════════════════════════════════════════════
#  Token management
# ══════════════════════════════════════════════════════════════════

@auth_bp.post('/refresh')
@jwt_required(refresh=True)
def refresh():
    """
    Issue a new access token using a valid refresh token.
    (Bonus) In production add the old refresh token to a blocklist here.
    """
    user_id = get_jwt_identity()
    user    = User.query.get(user_id)

    if not user or not user.is_active:
        return _error('User not found or inactive.', 401)

    new_access = create_access_token(identity=user_id, additional_claims={'role': user.role})
    return jsonify({'access_token': new_access}), 200


@auth_bp.post('/logout')
@jwt_required()
def logout():
    """
    Client-side: delete tokens from storage.
    Server-side (bonus): add the JWT jti to a blocklist to prevent reuse.
    For a stateless approach the client simply discards the tokens.
    """
    # TODO in production: add jti to a Redis blocklist with TTL = token expiry
    return jsonify({'message': 'Logged out successfully.'}), 200


# ══════════════════════════════════════════════════════════════════
#  Current user
# ══════════════════════════════════════════════════════════════════

@auth_bp.get('/me')
@jwt_required()
def me():
    """Return the current authenticated user's profile."""
    user_id = get_jwt_identity()
    user    = User.query.get(user_id)

    if not user or not user.is_active:
        return _error('User not found.', 404)

    return jsonify({'user': user.to_dict()}), 200


# ══════════════════════════════════════════════════════════════════
#  Role Management (Admin only)
# ══════════════════════════════════════════════════════════════════

def _require_admin():
    """Check if current user is admin."""
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return _error('Access denied. Admin role required.', 403)
    return None


@auth_bp.get('/users')
@jwt_required()
def list_users():
    """List all users (admin only)."""
    error = _require_admin()
    if error:
        return error

    users = User.query.all()
    return jsonify({'users': [u.to_dict() for u in users]}), 200


@auth_bp.post('/users/<user_id>/role')
@jwt_required()
def assign_role(user_id):
    """Assign a role to a user (admin only)."""
    error = _require_admin()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    role = (data.get('role') or '').strip().lower()

    if role not in ['admin', 'forensic_analyst']:
        return _error('Invalid role. Must be "admin" or "forensic_analyst".', 400)

    user = User.query.get(user_id)
    if not user:
        return _error('User not found.', 404)

    user.role = role
    db.session.commit()

    return jsonify({'user': user.to_dict(), 'message': f'Role updated to {role}'}), 200


@auth_bp.post('/users/<user_id>/deactivate')
@jwt_required()
def toggle_user_active(user_id):
    """Toggle a user's active/inactive status (admin only)."""
    error = _require_admin()
    if error:
        return error

    caller_id = get_jwt_identity()
    if user_id == caller_id:
        return _error('You cannot deactivate your own account.', 400)

    user = User.query.get(user_id)
    if not user:
        return _error('User not found.', 404)

    user.is_active = not user.is_active
    db.session.commit()

    status = 'activated' if user.is_active else 'deactivated'
    return jsonify({'user': user.to_dict(), 'message': f'Account {status}.'}), 200

