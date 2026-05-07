"""
OAuth state management and provider exchange helpers.

State tokens
------------
We use a simple in-process dict for the prototype.  In production replace
with Redis (key: state, value: 1, TTL: 5 min) so it works across workers.
"""

import os
import secrets
import requests
from flask import current_app

# ── In-process state store (replace with Redis in production) ──────
_state_store: dict[str, bool] = {}


def generate_state() -> str:
    """Create a cryptographically secure random state token and store it."""
    state = secrets.token_urlsafe(32)
    _state_store[state] = True
    return state


def validate_and_consume_state(state: str) -> bool:
    """Return True and remove the state if it is valid; False otherwise."""
    return _state_store.pop(state, None) is not None


# ── Google ─────────────────────────────────────────────────────────

GOOGLE_AUTH_URL  = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO  = 'https://www.googleapis.com/oauth2/v2/userinfo'


def google_auth_url(state: str) -> str:
    """Build the Google OAuth 2.0 authorization URL."""
    redirect_uri = _redirect_uri('google')
    params = '&'.join([
        f'client_id={current_app.config["GOOGLE_CLIENT_ID"]}',
        f'redirect_uri={redirect_uri}',
        'response_type=code',
        'scope=openid%20email%20profile',
        'access_type=offline',
        'prompt=select_account',
        f'state={state}',
    ])
    return f'{GOOGLE_AUTH_URL}?{params}'


def exchange_google_code(code: str) -> dict:
    """Exchange authorization code for user profile dict."""
    resp = requests.post(GOOGLE_TOKEN_URL, data={
        'code':          code,
        'client_id':     current_app.config['GOOGLE_CLIENT_ID'],
        'client_secret': current_app.config['GOOGLE_CLIENT_SECRET'],
        'redirect_uri':  _redirect_uri('google'),
        'grant_type':    'authorization_code',
    }, timeout=10)
    resp.raise_for_status()
    tokens = resp.json()

    user_resp = requests.get(GOOGLE_USERINFO, headers={
        'Authorization': f'Bearer {tokens["access_token"]}'
    }, timeout=10)
    user_resp.raise_for_status()
    data = user_resp.json()

    return {
        'provider_id':       data['id'],
        'email':             data['email'],
        'name':              data.get('name', ''),
        'profile_picture':   data.get('picture'),
    }


# ── GitHub ─────────────────────────────────────────────────────────

GITHUB_AUTH_URL  = 'https://github.com/login/oauth/authorize'
GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_USERINFO  = 'https://api.github.com/user'
GITHUB_EMAILS    = 'https://api.github.com/user/emails'


def github_auth_url(state: str) -> str:
    """Build the GitHub OAuth 2.0 authorization URL."""
    redirect_uri = _redirect_uri('github')
    params = '&'.join([
        f'client_id={current_app.config["GITHUB_CLIENT_ID"]}',
        f'redirect_uri={redirect_uri}',
        'scope=read:user%20user:email',
        f'state={state}',
    ])
    return f'{GITHUB_AUTH_URL}?{params}'


def exchange_github_code(code: str) -> dict:
    """Exchange authorization code for user profile dict."""
    resp = requests.post(GITHUB_TOKEN_URL, headers={'Accept': 'application/json'}, data={
        'code':          code,
        'client_id':     current_app.config['GITHUB_CLIENT_ID'],
        'client_secret': current_app.config['GITHUB_CLIENT_SECRET'],
        'redirect_uri':  _redirect_uri('github'),
    }, timeout=10)
    resp.raise_for_status()
    tokens = resp.json()
    access_token = tokens['access_token']

    headers = {'Authorization': f'token {access_token}', 'Accept': 'application/json'}

    user_resp = requests.get(GITHUB_USERINFO, headers=headers, timeout=10)
    user_resp.raise_for_status()
    data = user_resp.json()

    # GitHub may not expose email in the main endpoint
    email = data.get('email')
    if not email:
        emails_resp = requests.get(GITHUB_EMAILS, headers=headers, timeout=10)
        emails_resp.raise_for_status()
        primary = next(
            (e['email'] for e in emails_resp.json() if e.get('primary') and e.get('verified')),
            None
        )
        email = primary

    if not email:
        raise ValueError('GitHub account does not have a verified public email address')

    return {
        'provider_id':     str(data['id']),
        'email':           email,
        'name':            data.get('name') or data.get('login', ''),
        'profile_picture': data.get('avatar_url'),
    }


# ── Private helpers ────────────────────────────────────────────────

def _redirect_uri(provider: str) -> str:
    base = current_app.config['BACKEND_URL']
    return f'{base}/api/auth/{provider}/callback'
