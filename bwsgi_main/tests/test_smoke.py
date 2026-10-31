"""Smoke and regression tests for Bwsgi. Run: python -m unittest discover -v."""
import io
import json
import os
import subprocess
import sys
import threading
import unittest
from contextlib import redirect_stdout
from tempfile import TemporaryDirectory
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import patch

from bwsgi import Bwsgi, CORSMiddleware, Response, csrf_protect
from bwsgi.auth import hash_password, verify_password
from bwsgi.core import _source_snapshot, _watch_sources
from bwsgi.db import Database


def request(app, path, method="GET", body=b"", extra_environ=None):
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "wsgi.input": io.BytesIO(body),
        "CONTENT_LENGTH": str(len(body)),
    }
    if extra_environ:
        environ.update(extra_environ)
    captured["body"] = b"".join(app(environ, start_response))
    return captured


class BwsgiTests(unittest.TestCase):
    def test_production_mode_requires_strong_secret(self):
        for secret_key in (None, "", "x" * 31):
            with self.subTest(secret_key=secret_key):
                with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
                    Bwsgi(
                        db_path=":memory:",
                        secret_key=secret_key,
                        production=True,
                    )

    def test_production_mode_disables_debug_and_forces_secure_cookies(self):
        app = Bwsgi(
            db_path=":memory:",
            secret_key="p" * 32,
            debug=True,
            production=True,
        )
        self.assertFalse(app.config["DEBUG"])
        self.assertTrue(app.config["SESSION_COOKIE_SECURE"])

        @app.route("/session")
        def session(req):
            req.session["active"] = True
            return Response.text("ok")

        @app.route("/failure")
        def failure(req):
            raise RuntimeError("internal-production-detail")

        app.config["DEBUG"] = True
        app.config["SESSION_COOKIE_SECURE"] = False
        response = request(app, "/session")
        cookie = next(
            value for name, value in response["headers"]
            if name == "Set-Cookie"
        )
        self.assertIn("; Secure", cookie)

        with self.assertLogs("bwsgi", level="ERROR") as captured:
            failed = request(app, "/failure")
        self.assertEqual(failed["status"], "500 Internal Server Error")
        self.assertNotIn(b"internal-production-detail", failed["body"])
        self.assertNotIn("Traceback", failed["body"].decode())
        self.assertIn("internal-production-detail", "\n".join(captured.output))

    def test_development_mode_retains_generated_secret_defaults(self):
        app = Bwsgi(db_path=":memory:")
        self.assertFalse(app.production)
        self.assertGreaterEqual(len(app.config["SECRET_KEY"].encode()), 32)
        self.assertFalse(app.config["DEBUG"])
        self.assertIsNone(app.config["SESSION_COOKIE_SECURE"])

    def test_passenger_requires_secret_and_disables_debug(self):
        project_root = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as directory:
            env = os.environ.copy()
            env.pop("BWSGI_SECRET_KEY", None)
            env["BWSGI_DB_PATH"] = str(Path(directory, "passenger.db"))
            missing_secret = subprocess.run(
                [sys.executable, "-c", "import passenger_wsgi"],
                cwd=project_root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(missing_secret.returncode, 0)
            self.assertIn("secret_key", missing_secret.stderr)

            env["BWSGI_SECRET_KEY"] = "too-short"
            weak_secret = subprocess.run(
                [sys.executable, "-c", "import passenger_wsgi"],
                cwd=project_root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(weak_secret.returncode, 0)
            self.assertIn("at least 32 bytes", weak_secret.stderr)

            env["BWSGI_SECRET_KEY"] = "a" * 32
            production_import = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import io, passenger_wsgi; "
                        "app = passenger_wsgi.application; "
                        "assert app.config['DEBUG'] is False; "
                        "assert app.config['SESSION_COOKIE_SECURE'] is True; "
                        "assert app.production is True; "
                        "response = {}; "
                        "start = lambda status, headers: response.update("
                        "status=status, headers=headers); "
                        "env = {'REQUEST_METHOD': 'GET', "
                        "'PATH_INFO': '/login', 'QUERY_STRING': '', "
                        "'CONTENT_LENGTH': '0', 'wsgi.input': io.BytesIO()}; "
                        "list(app(env, start)); "
                        "assert any(name == 'Set-Cookie' and '; Secure' "
                        "in value for name, value in response['headers'])"
                    ),
                ],
                cwd=project_root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                production_import.returncode,
                0,
                production_import.stderr,
            )

    def test_secure_session_cookie_can_be_forced_behind_proxy(self):
        app = Bwsgi(db_path=":memory:", secret_key="test-key")
        app.config["SESSION_COOKIE_SECURE"] = True

        @app.route("/session")
        def session(req):
            req.session["active"] = True
            return Response.text("ok")

        response = request(app, "/session")
        cookie = next(
            value for name, value in response["headers"]
            if name == "Set-Cookie"
        )
        self.assertIn("; Secure", cookie)

    def test_request_body_limit_rejects_oversized_and_invalid_lengths(self):
        app = Bwsgi(db_path=":memory:", max_content_length=4)

        @app.route("/body", methods=("POST",))
        def body(req):
            return Response.text(req.body.decode())

        oversized = request(
            app, "/body", "POST", extra_environ={"CONTENT_LENGTH": "5"}
        )
        self.assertEqual(oversized["status"], "413 Payload Too Large")
        self.assertEqual(oversized["body"], b"Request Entity Too Large")

        huge_length = request(
            app, "/body", "POST",
            extra_environ={"CONTENT_LENGTH": "9" * 5000},
        )
        self.assertEqual(huge_length["status"], "413 Payload Too Large")

        malformed = request(
            app, "/body", "POST", extra_environ={"CONTENT_LENGTH": "4x"}
        )
        self.assertEqual(malformed["status"], "400 Bad Request")
        self.assertEqual(malformed["body"], b"Invalid Content-Length")

        accepted = request(
            app, "/body", "POST", body=b"four",
        )
        self.assertEqual(accepted["status"], "200 OK")
        self.assertEqual(accepted["body"], b"four")

    def test_max_content_length_must_be_non_negative_integer(self):
        for value in (-1, 1.5, True, "1024"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Bwsgi(db_path=":memory:", max_content_length=value)

    def test_database_reopens_connection_after_process_change(self):
        db = Database(":memory:")
        original = db.conn
        db._local.pid = -1
        replacement = db.conn
        self.assertIsNot(original, replacement)
        self.assertIsNotNone(db.fetchone("SELECT 1"))
        original.close()
        replacement.close()

    def test_unhandled_errors_are_logged_without_debug_response(self):
        app = Bwsgi(db_path=":memory:", debug=False)

        @app.route("/failure")
        def failure(req):
            raise RuntimeError("internal-only-detail")

        with self.assertLogs("bwsgi", level="ERROR") as captured:
            response = request(app, "/failure")
        self.assertEqual(response["status"], "500 Internal Server Error")
        self.assertNotIn(b"internal-only-detail", response["body"])
        self.assertNotIn(b"Traceback", response["body"])
        self.assertIn("internal-only-detail", "\n".join(captured.output))

    def test_cors_preflight_and_origin_allowlist(self):
        app = Bwsgi(db_path=":memory:")

        @app.route("/api", methods=("GET", "POST"))
        def api(req):
            return Response.json({"ok": True})

        app.add_middleware(CORSMiddleware(
            allowed_origins=("https://example.com",),
            allowed_methods=("GET", "POST"),
            allowed_headers=("X-Token",),
            expose_headers=("X-Result",),
        ))

        preflight = request(app, "/api", "OPTIONS", extra_environ={
            "HTTP_ORIGIN": "https://example.com",
            "HTTP_ACCESS_CONTROL_REQUEST_METHOD": "POST",
            "HTTP_ACCESS_CONTROL_REQUEST_HEADERS": "X-Token",
        })
        self.assertEqual(preflight["status"], "204 No Content")
        self.assertIn(
            ("Access-Control-Allow-Origin", "https://example.com"),
            preflight["headers"],
        )
        self.assertIn(
            ("Access-Control-Allow-Headers", "X-Token"),
            preflight["headers"],
        )
        self.assertIn(("Vary", (
            "Origin, Access-Control-Request-Method, "
            "Access-Control-Request-Headers"
        )), preflight["headers"])

        allowed = request(app, "/api", extra_environ={
            "HTTP_ORIGIN": "https://example.com",
        })
        self.assertEqual(allowed["status"], "200 OK")
        self.assertIn(
            ("Access-Control-Expose-Headers", "X-Result"),
            allowed["headers"],
        )

        def app_with_existing_vary(environ, start_response):
            start_response("200 OK", [("Vary", "Accept-Encoding")])
            return [b"cached"]

        cors = CORSMiddleware(
            allowed_origins=("https://example.com",),
        )(app_with_existing_vary)
        vary_response = {}

        def capture_response(status, headers):
            vary_response["headers"] = headers

        list(cors({
            "REQUEST_METHOD": "GET",
            "HTTP_ORIGIN": "https://example.com",
        }, capture_response))
        vary = next(
            value for name, value in vary_response["headers"]
            if name.lower() == "vary"
        )
        self.assertEqual(vary, "Accept-Encoding, Origin")

        denied = request(app, "/api", extra_environ={
            "HTTP_ORIGIN": "https://other.example",
        })
        self.assertNotIn(
            "Access-Control-Allow-Origin",
            dict(denied["headers"]),
        )

    def test_cors_wildcard_cannot_allow_credentials(self):
        with self.assertRaises(ValueError):
            CORSMiddleware(
                allowed_origins="*",
                allow_credentials=True,
            )

    def test_debug_source_snapshot_tracks_app_files_not_virtualenv(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            app_file = root / "app.py"
            app_file.write_text("value = 1\n", encoding="utf-8")
            virtualenv = root / "venv"
            virtualenv.mkdir()
            (virtualenv / "dependency.py").write_text(
                "value = 1\n", encoding="utf-8"
            )

            initial = _source_snapshot(root)
            app_file.write_text("value = 2\n", encoding="utf-8")
            self.assertNotEqual(_source_snapshot(root), initial)

            current = _source_snapshot(root)
            (virtualenv / "dependency.py").write_text(
                "value = 2\n", encoding="utf-8"
            )
            self.assertEqual(_source_snapshot(root), current)

    def test_debug_reloader_restarts_when_source_changes(self):
        with patch("bwsgi.core.time.sleep"):
            with patch(
                "bwsgi.core._source_snapshot",
                return_value={"app.py": (1, 1)},
            ):
                with patch(
                    "bwsgi.core.os.execv",
                    side_effect=RuntimeError("restarted"),
                ) as execv:
                    with redirect_stdout(io.StringIO()):
                        with self.assertRaisesRegex(RuntimeError, "restarted"):
                            _watch_sources(Path("."), {})

        execv.assert_called_once_with(
            sys.executable, [sys.executable] + sys.argv
        )

    def test_password_roundtrip(self):
        hashed, salt = hash_password("hunter2")
        self.assertTrue(verify_password("hunter2", hashed, salt))
        self.assertFalse(verify_password("wrong", hashed, salt))

    def test_memory_database_stays_in_memory(self):
        app = Bwsgi(db_path=":memory:")
        self.assertIn("mode=memory", app.db.db_path)
        self.assertIsNotNone(app.db.fetchone("SELECT name FROM sqlite_master"))
        result = []

        def read_schema():
            result.append(app.db.fetchone("SELECT name FROM sqlite_master"))

        thread = threading.Thread(target=read_schema)
        thread.start()
        thread.join()
        self.assertTrue(result)

    def test_debug_setting_defaults_to_off(self):
        self.assertFalse(Bwsgi(db_path=":memory:").config["DEBUG"])

    def test_builtin_server_is_labeled_as_development_only(self):
        app = Bwsgi(db_path=":memory:")
        output = io.StringIO()
        with patch("wsgiref.simple_server.make_server") as make_server:
            make_server.return_value.__enter__.return_value.serve_forever = (
                lambda: None
            )
            with redirect_stdout(output):
                app.run()
        self.assertIn("DEVELOPMENT WSGI SERVER (wsgiref)", output.getvalue())
        self.assertIn("DEVELOPMENT SERVER", output.getvalue())
        self.assertNotIn("PRODUCTION", output.getvalue())

    def test_builtin_server_is_blocked_in_production_mode(self):
        app = Bwsgi(
            db_path=":memory:",
            secret_key="p" * 32,
            production=True,
        )
        with patch("wsgiref.simple_server.make_server") as make_server:
            with self.assertRaisesRegex(
                RuntimeError,
                "development server cannot run in production mode",
            ):
                app.run()
        make_server.assert_not_called()

    def test_route_parameters_and_url_for(self):
        app = Bwsgi(db_path=":memory:")

        @app.route("/users/<username>")
        def user(req, username):
            return Response.text(username)

        self.assertEqual(app.url_for("user", username="Jane Doe"), "/users/Jane%20Doe")
        response = request(app, "/users/Jane Doe")
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(response["body"], b"Jane Doe")

    def test_method_not_allowed_returns_allow_header(self):
        app = Bwsgi(db_path=":memory:")

        @app.route("/submit", methods=("POST",))
        def submit(req):
            return Response.text("submitted")

        response = request(app, "/submit")
        self.assertEqual(response["status"], "405 Method Not Allowed")
        self.assertIn(("Allow", "POST"), response["headers"])

    def test_invalid_json_returns_bad_request(self):
        app = Bwsgi(db_path=":memory:")

        @app.route("/json", methods=("POST",))
        def json_view(req):
            return Response.json(req.json())

        response = request(app, "/json", method="POST", body=b"{invalid")
        self.assertEqual(response["status"], "400 Bad Request")

    def test_static_prefix_does_not_capture_neighboring_paths(self):
        app = Bwsgi(db_path=":memory:")
        app.config["STATIC_DIR"] = "static"

        @app.route("/staticized")
        def staticized(req):
            return Response.text("route")

        response = request(app, "/staticized")
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(response["body"], b"route")

    def test_static_file_serving_and_traversal_protection(self):
        with TemporaryDirectory() as static_dir:
            Path(static_dir, "hello.txt").write_text("hello", encoding="utf-8")
            app = Bwsgi(db_path=":memory:", static_dir=static_dir)

            served = request(app, "/static/hello.txt")
            self.assertEqual(served["status"], "200 OK")
            self.assertEqual(served["body"], b"hello")

            escaped = request(app, "/static/../secret.txt")
            self.assertEqual(escaped["status"], "403 Forbidden")

    def test_file_response_yields_bounded_chunks(self):
        with TemporaryDirectory() as directory:
            path = Path(directory, "large.bin")
            path.write_bytes(b"x" * (128 * 1024 + 1))
            _, _, body = Response.file(path)
            chunks = iter(body)
            self.assertEqual(len(next(chunks)), 64 * 1024)
            self.assertEqual(len(next(chunks)), 64 * 1024)
            self.assertEqual(next(chunks), b"x")
            with self.assertRaises(StopIteration):
                next(chunks)

    def test_json_schema_validation(self):
        app = Bwsgi(db_path=":memory:")

        @app.route("/api/items", methods=("POST",))
        def create_item(req):
            data = req.validate_json({"name": str, "quantity": int})
            return Response.json(data, "201 Created")

        valid = request(
            app, "/api/items", "POST",
            json.dumps({"name": "book", "quantity": 3}).encode(),
        )
        self.assertEqual(valid["status"], "201 Created")

        invalid = request(
            app, "/api/items", "POST",
            json.dumps({"name": "book", "quantity": "three"}).encode(),
        )
        self.assertEqual(invalid["status"], "400 Bad Request")
        self.assertIn(b'"quantity": "Expected int"', invalid["body"])

    def test_session_and_csrf_protection(self):
        app = Bwsgi(db_path=":memory:", secret_key="test-secret")

        @app.route("/token")
        def token(req):
            return Response.json({"csrf": req.csrf_token()})

        @app.route("/change", methods=("POST",))
        @csrf_protect
        def change(req):
            req.session["changed"] = True
            return Response.json({"changed": True})

        @app.route("/state")
        def state(req):
            return Response.json({"changed": req.session.get("changed", False)})

        initial = request(
            app, "/token", extra_environ={"wsgi.url_scheme": "https"}
        )
        self.assertTrue(any(
            key == "Set-Cookie" and "; Secure" in value
            for key, value in initial["headers"]
        ))
        session_cookie = next(
            value.split(";", 1)[0]
            for key, value in initial["headers"]
            if key == "Set-Cookie"
        )
        csrf = json.loads(initial["body"])["csrf"]

        rejected = request(
            app, "/change", "POST",
            extra_environ={"HTTP_COOKIE": session_cookie},
        )
        self.assertEqual(rejected["status"], "403 Forbidden")

        accepted = request(
            app, "/change", "POST",
            extra_environ={
                "HTTP_COOKIE": session_cookie,
                "HTTP_X_CSRF_TOKEN": csrf,
            },
        )
        self.assertEqual(accepted["status"], "200 OK")
        updated_cookie = next(
            value.split(";", 1)[0]
            for key, value in accepted["headers"]
            if key == "Set-Cookie"
        )
        state = request(
            app, "/state", extra_environ={"HTTP_COOKIE": updated_cookie}
        )
        self.assertEqual(json.loads(state["body"]), {"changed": True})

    def test_csrf_form_field_is_supported(self):
        app = Bwsgi(db_path=":memory:")

        @app.route("/token")
        def token(req):
            return Response.text(req.csrf_token())

        @app.route("/submit", methods=("POST",))
        @csrf_protect
        def submit(req):
            return Response.text(req.form()["value"])

        initial = request(app, "/token")
        cookie = next(
            value.split(";", 1)[0]
            for key, value in initial["headers"]
            if key == "Set-Cookie"
        )
        token_value = initial["body"].decode()
        form = urlencode({"_csrf_token": token_value, "value": "ok"}).encode()
        result = request(
            app, "/submit", "POST", form,
            {"HTTP_COOKIE": cookie},
        )
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["body"], b"ok")

    def test_session_survives_app_recreation_with_same_secret(self):
        with TemporaryDirectory() as directory:
            db_path = str(Path(directory, "sessions.db"))
            first_app = Bwsgi(db_path=db_path, secret_key="persistent-test-key")

            @first_app.route("/create")
            def create(req):
                req.session["user_id"] = 42
                return Response.text("created")

            created = request(first_app, "/create")
            cookie = next(
                value.split(";", 1)[0]
                for key, value in created["headers"]
                if key == "Set-Cookie"
            )

            second_app = Bwsgi(db_path=db_path, secret_key="persistent-test-key")

            @second_app.route("/read")
            def read(req):
                return Response.json({"user_id": req.session.get("user_id")})

            restored = request(
                second_app, "/read", extra_environ={"HTTP_COOKIE": cookie}
            )
            self.assertEqual(json.loads(restored["body"]), {"user_id": 42})
            first_app.db.conn.close()
            second_app.db.conn.close()

    def test_exception_class_error_handler(self):
        app = Bwsgi(db_path=":memory:")

        @app.route("/failure")
        def failure(req):
            raise ValueError("bad input")

        @app.errorhandler(ValueError)
        def invalid_value(req):
            return Response.json({"error": "invalid value"}, "400 Bad Request")

        response = request(app, "/failure")
        self.assertEqual(response["status"], "400 Bad Request")
        self.assertEqual(json.loads(response["body"]), {"error": "invalid value"})

    def test_template_escaping_and_middleware(self):
        with TemporaryDirectory() as template_dir:
            Path(template_dir, "hello.html").write_text(
                "<h1>{{ name }}</h1>", encoding="utf-8"
            )
            app = Bwsgi(db_path=":memory:", template_dir=template_dir)

            @app.route("/")
            def home(req):
                return app.render_template("hello.html", name="<script>")

            def add_header(inner_app):
                def middleware(environ, start_response):
                    def add_response_header(status, headers):
                        return start_response(
                            status, headers + [("X-Middleware", "enabled")]
                        )
                    return inner_app(environ, add_response_header)
                return middleware

            app.add_middleware(add_header)
            response = request(app, "/")
            self.assertEqual(response["status"], "200 OK")
            self.assertIn(b"&lt;script&gt;", response["body"])
            self.assertIn(("X-Middleware", "enabled"), response["headers"])


if __name__ == "__main__":
    unittest.main()
