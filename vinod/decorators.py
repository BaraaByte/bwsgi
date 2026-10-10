"""Auth decorators."""
from functools import wraps
import hmac

from .core import Response


_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def login_required(view):
    """Redirect unauthenticated users to /login."""
    @wraps(view)
    def wrapper(req, *args, **kwargs):
        if req.user is None:
            return Response.redirect("/login")
        return view(req, *args, **kwargs)
    return wrapper


def csrf_protect(view):
    """Require a session CSRF token for requests that can change state."""
    @wraps(view)
    def wrapper(req, *args, **kwargs):
        if req.method not in _SAFE_METHODS:
            supplied = req.headers.get("X-Csrf-Token")
            if supplied is None:
                supplied = req.form().get("_csrf_token")
            expected = req.session.get("_csrf_token")
            if (not supplied or not expected
                    or not hmac.compare_digest(supplied, expected)):
                return Response.text("CSRF token missing or invalid", "403 Forbidden")
        return view(req, *args, **kwargs)
    return wrapper
