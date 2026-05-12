from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt, jwt_required

ADMIN   = 'admin'
ANALYST = 'forensic_analyst'

ALL_VALID_ROLES = {ADMIN, ANALYST}


def require_role(*allowed_roles: str):
    """
    Decorator that enforces JWT presence and role membership.

    Usage::

        @bp.get('/admin-only')
        @require_role(ADMIN)
        def admin_view(): ...
    """
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            role = get_jwt().get('role', '')
            if role not in allowed_roles:
                return jsonify({
                    'message': 'Access denied — insufficient role.',
                    'required': list(allowed_roles),
                    'your_role': role,
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator
