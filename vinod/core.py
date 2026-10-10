"""Vinod core - WSGI application, router, request, response."""
import re
import json
import traceback
import mimetypes
import secrets
import copy
import hmac
import hashlib
import html
from pathlib import Path
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

from .auth import session_expiry
from .db import Database


class RequestValidationError(ValueError):
    """Raised when parsed request data does not satisfy a declared shape."""

    def __init__(self, errors):
        self.errors = errors
        super().__init__("Request validation failed")


class Request:
    """Lightweight request context passed to every view."""

    def __init__(self, environ, db, app):
        self.environ = environ
        self.db = db
        self.app = app
        self.method = environ["REQUEST_METHOD"].upper()
        parsed = urlparse(environ.get("PATH_INFO", "/"))
        self.path = parsed.path
        self.query = {k: v[0] for k, v in
                      parse_qs(environ.get("QUERY_STRING", "")).items()}
        self.headers = {
            k[5:].replace("_", "-").title(): v
            for k, v in environ.items() if k.startswith("HTTP_")
        }
        self.cookies = SimpleCookie()
        if "HTTP_COOKIE" in environ:
            self.cookies.load(environ["HTTP_COOKIE"])
        self.user = None
        self._body = None
        self.session = {}
        self._session_id = None
        self._session_snapshot = {}

    def load_session(self):
        self.session, self._session_id = self.app._load_session(self)
        self._session_snapshot = copy.deepcopy(self.session)

    @property
    def body(self) -> bytes:
        if self._body is None:
            try:
                length = int(self.environ.get("CONTENT_LENGTH") or 0)
            except ValueError:
                length = 0
            self._body = (self.environ["wsgi.input"].read(length)
                          if length else b"")
        return self._body

    def json(self) -> Any:
        if not self.body:
            return {}
        return json.loads(self.body.decode("utf-8"))

    def validate_json(self, schema: dict[str, type]) -> dict:
        """Parse an object and require each key to have the declared type."""
        data = self.json()
        if not isinstance(data, dict):
            raise RequestValidationError({"$": "Expected a JSON object"})

        errors = {}
        for key, expected_type in schema.items():
            if key not in data:
                errors[key] = "Required field is missing"
            elif (not isinstance(data[key], expected_type)
                  or (expected_type is int and isinstance(data[key], bool))):
                errors[key] = f"Expected {expected_type.__name__}"
        if errors:
            raise RequestValidationError(errors)
        return data

    def csrf_token(self) -> str:
        token = self.session.get("_csrf_token")
        if token is None:
            token = secrets.token_urlsafe(32)
            self.session["_csrf_token"] = token
        return token

    def form(self) -> dict:
        return {k: v[0] for k, v in
                parse_qs(self.body.decode("utf-8")).items()}

    def url_for(self, name: str, **params) -> str:
        return self.app.url_for(name, **params)

    @property
    def response(self):
        return Response


class Response:
    """Convenience response builders."""

    @staticmethod
    def text(body, status="200 OK", headers=None):
        h = [("Content-Type", "text/plain; charset=utf-8")]
        if headers:
            h.extend(headers)
        return status, h, [body.encode("utf-8")]

    @staticmethod
    def html(body, status="200 OK", headers=None):
        h = [("Content-Type", "text/html; charset=utf-8")]
        if headers:
            h.extend(headers)
        return status, h, [body.encode("utf-8")]

    @staticmethod
    def json(data, status="200 OK", headers=None):
        h = [("Content-Type", "application/json")]
        if headers:
            h.extend(headers)
        return status, h, [json.dumps(data).encode("utf-8")]

    @staticmethod
    def redirect(location, status="302 Found", headers=None):
        h = [("Location", location)]
        if headers:
            h.extend(headers)
        return status, h, [b""]

    @staticmethod
    def file(path, status="200 OK", headers=None):
        mime, _ = mimetypes.guess_type(path)
        h = [("Content-Type", mime or "application/octet-stream")]
        if headers:
            h.extend(headers)

        def chunks():
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    yield chunk

        return status, h, chunks()


class Vinod:
    """The main WSGI application."""

    def __init__(self, db_path="app.db", static_dir="static",
                 static_url="/static", debug=False, secret_key=None,
                 template_dir="templates"):
        self.db = Database(db_path)
        self.routes = []
        self.before_hooks = []
        self.after_hooks = []
        self.error_handlers = {}
        self.extensions = {}
        self._wsgi_app = self._dispatch
        self.config = {
            "DEBUG": debug,
            "SECRET_KEY": secret_key or secrets.token_hex(32),
            "SESSION_DAYS": 7,
            "STATIC_DIR": static_dir,
            "STATIC_URL": static_url,
            "TEMPLATE_DIR": template_dir,
            "SESSION_COOKIE_NAME": "vinod_session",
            "DB_PATH": db_path,
        }

    def route(self, path, methods=("GET",)):
        def decorator(view):
            regex = self._compile_path(path)
            for m in methods:
                self.routes.append(
                    (m.upper(), regex, view, path, view.__name__))
            return view
        return decorator

    @staticmethod
    def _compile_path(path):
        parts = re.split(r"(<[A-Za-z_]\w*>)", path)
        pattern = "".join(
            f"(?P<{part[1:-1]}>[^/]+)" if part.startswith("<") else re.escape(part)
            for part in parts
        )
        return re.compile(f"^{pattern}$")

    def _match(self, method, path):
        for m, regex, view, _, _ in self.routes:
            if m != method:
                continue
            match = regex.match(path)
            if match:
                return view, match.groupdict()
        return None, None

    def url_for(self, name, **params):
        for _, _, _, path, route_name in self.routes:
            if route_name == name:
                return re.sub(
                    r"<([A-Za-z_]\w*)>",
                    lambda match: quote(str(params[match.group(1)]), safe=""),
                    path,
                )
        raise KeyError(f"No route named {name!r}")

    def before_request(self, f):
        self.before_hooks.append(f)
        return f

    def after_request(self, f):
        self.after_hooks.append(f)
        return f

    def add_middleware(self, factory):
        """Wrap the WSGI application with a middleware factory."""
        wrapped = factory(self._wsgi_app)
        if not callable(wrapped):
            raise TypeError("Middleware factory must return a WSGI callable")
        self._wsgi_app = wrapped
        return factory

    def errorhandler(self, code):
        def decorator(f):
            self.error_handlers[code] = f
            return f
        return decorator

    def render_template(self, template_name: str, **context) -> tuple:
        """Render a UTF-8 HTML template with HTML-escaped {{ name }} values."""
        root = Path(self.config["TEMPLATE_DIR"]).resolve()
        path = (root / template_name).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError("Template path must stay inside TEMPLATE_DIR") from exc
        source = path.read_text(encoding="utf-8")

        def replace(match):
            key = match.group(1)
            if key not in context:
                raise KeyError(f"Missing template value {key!r}")
            return html.escape(str(context[key]), quote=True)

        body = re.sub(r"{{\s*([A-Za-z_]\w*)\s*}}", replace, source)
        return Response.html(body)

    def register(self, extension):
        """Register a Vinod extension. Extension must expose init_app(app)."""
        name = extension.__class__.__name__.lower()
        if hasattr(extension, "init_app"):
            extension.init_app(self)
        self.extensions[name] = extension
        return extension

    def _sign_session_id(self, session_id):
        return hmac.new(
            self.config["SECRET_KEY"].encode("utf-8"),
            session_id.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _load_session(self, req):
        cookie = req.cookies.get(self.config.get("SESSION_COOKIE_NAME", "vinod_session"))
        if not cookie:
            return {}, None
        try:
            session_id, signature = cookie.value.split(".", 1)
        except ValueError:
            return {}, None
        if (re.fullmatch(r"[A-Za-z0-9_-]{43}", session_id) is None
                or re.fullmatch(r"[a-f0-9]{64}", signature) is None):
            return {}, None
        if not hmac.compare_digest(signature, self._sign_session_id(session_id)):
            return {}, None
        row = self.db.fetchone(
            "SELECT data FROM web_sessions "
            "WHERE id = ? AND expires_at > datetime('now')",
            (session_id,),
        )
        if row is None:
            return {}, None
        data = json.loads(row["data"])
        if not isinstance(data, dict):
            raise ValueError("Stored session data must be a JSON object")
        return data, session_id

    def _save_session(self, req, result):
        if req.session == req._session_snapshot:
            return result

        session_id = req._session_id or secrets.token_urlsafe(32)
        expires_at = session_expiry(self.config["SESSION_DAYS"])
        self.db.execute(
            "DELETE FROM web_sessions WHERE expires_at <= datetime('now')"
        )
        self.db.execute(
            "INSERT INTO web_sessions (id, data, expires_at) VALUES (?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET data = excluded.data, "
            "expires_at = excluded.expires_at",
            (session_id, json.dumps(req.session), expires_at),
        )
        signature = self._sign_session_id(session_id)
        secure = "; Secure" if req.environ.get("wsgi.url_scheme") == "https" else ""
        cookie = (
            f"{self.config['SESSION_COOKIE_NAME']}={session_id}.{signature}; "
            f"Path=/; HttpOnly; SameSite=Lax; "
            f"Max-Age={self.config['SESSION_DAYS'] * 86400}{secure}"
        )
        status, headers, body = result
        return status, headers + [("Set-Cookie", cookie)], body

    def _load_user(self, req):
        cookie = req.cookies.get("sessionid")
        if not cookie:
            return
        row = self.db.fetchone(
            "SELECT u.id, u.username FROM sessions s "
            "JOIN users u ON u.id = s.user_id "
            "WHERE s.token = ? AND s.expires_at > datetime('now')",
            (cookie.value,),
        )
        if row:
            req.user = {"id": row["id"], "username": row["username"]}

    def _serve_static(self, req, start_response):
        static_url = self.config["STATIC_URL"].rstrip("/") or "/"
        rel = (req.path.lstrip("/") if static_url == "/"
               else req.path[len(static_url):].lstrip("/"))
        root = Path(self.config["STATIC_DIR"]).resolve()
        full = (root / rel).resolve()
        try:
            full.relative_to(root)
        except ValueError:
            return self._emit(Response.text("403 Forbidden", "403 Forbidden"),
                              start_response)
        if not full.is_file():
            return self._emit(Response.text("404 Not Found", "404 Not Found"),
                              start_response)
        return self._emit(Response.file(full), start_response)

    def __call__(self, environ, start_response):
        return self._wsgi_app(environ, start_response)

    def _dispatch(self, environ, start_response):
        req = None
        try:
            req = Request(environ, self.db, self)

            static_url = self.config["STATIC_URL"].rstrip("/") or "/"
            if (static_url == "/" or req.path == static_url
                    or req.path.startswith(static_url + "/")):
                return self._serve_static(req, start_response)

            req.load_session()
            self._load_user(req)

            for hook in self.before_hooks:
                result = hook(req)
                if result is not None:
                    return self._emit_result(result, req, start_response)

            view, kwargs = self._match(req.method, req.path)
            if view is None:
                allowed = sorted({
                    route_method for route_method, regex, _, _, _ in self.routes
                    if regex.match(req.path)
                })
                if allowed:
                    result = Response.text(
                        "405 Method Not Allowed",
                        "405 Method Not Allowed",
                        headers=[("Allow", ", ".join(allowed))],
                    )
                    return self._emit_result(result, req, start_response)
                handler = self.error_handlers.get(404)
                result = (handler(req) if handler
                          else Response.text("404 Not Found", "404 Not Found"))
                return self._emit_result(result, req, start_response)

            result = view(req, **kwargs) if kwargs else view(req)
            return self._emit_result(result, req, start_response)

        except Exception as exc:
            handler = next((
                callback for key, callback in self.error_handlers.items()
                if isinstance(key, type) and isinstance(exc, key)
            ), None)
            if handler and req is not None:
                return self._emit(handler(req), start_response)
            if isinstance(exc, RequestValidationError):
                return self._emit(Response.json(
                    {"error": "Invalid request", "details": exc.errors},
                    "400 Bad Request",
                ), start_response)
            if isinstance(exc, (json.JSONDecodeError, UnicodeDecodeError)):
                return self._emit(Response.json(
                    {"error": "Invalid request body"},
                    "400 Bad Request",
                ), start_response)
            tb = traceback.format_exc() if self.config["DEBUG"] else ""
            handler = self.error_handlers.get(500)
            if handler and req is not None:
                result = handler(req)
            else:
                body = "<h1>500 Internal Server Error</h1>"
                if tb:
                    body += f"<pre>{html.escape(tb)}</pre>"
                result = Response.html(body, "500 Internal Server Error")
            return self._emit(result, start_response)

    def _emit_result(self, result, req, start_response):
        for hook in self.after_hooks:
            result = hook(req, result) or result
        result = self._save_session(req, result)
        return self._emit(result, start_response)

    @staticmethod
    def _emit(result, start_response):
        status, headers, body = result
        start_response(status, headers)
        return body

    def run(self, host="127.0.0.1", port=8000):
        from wsgiref.simple_server import make_server
        print(f"Vinod running on http://{host}:{port}")
        with make_server(host, port, self) as httpd:
            httpd.serve_forever()
