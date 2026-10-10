"""Smoke and regression tests for Bwsgi. Run: python -m unittest discover -v."""
import io
import json
import threading
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from urllib.parse import urlencode

from bwsgi import Bwsgi, Response, csrf_protect
from bwsgi.auth import hash_password, verify_password


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
