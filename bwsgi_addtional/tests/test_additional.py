import gzip
import unittest
from types import SimpleNamespace

from bwsgi_additional import (
    CORSMiddleware,
    GZipMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
    flash,
    get_flashed_messages,
    paginate,
    rate_limit,
)


def invoke(app, environ=None):
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers

    request_environ = {"REQUEST_METHOD": "GET"}
    if environ:
        request_environ.update(environ)
    body = b"".join(app(request_environ, start_response))
    return captured, body, request_environ


class AdditionalTests(unittest.TestCase):
    def test_request_id_is_echoed_or_generated(self):
        def app(environ, start_response):
            start_response("200 OK", [])
            return [environ["bwsgi.request_id"].encode()]

        middleware = RequestIDMiddleware()(app)
        response, body, _ = invoke(
            middleware, {"HTTP_X_REQUEST_ID": "req-123"}
        )
        self.assertEqual(body, b"req-123")
        self.assertIn(("X-Request-ID", "req-123"), response["headers"])

        response, body, _ = invoke(
            middleware, {"HTTP_X_REQUEST_ID": "bad\r\nheader"}
        )
        self.assertEqual(len(body), 32)
        self.assertIn(("X-Request-ID", body.decode()), response["headers"])

    def test_security_headers_preserve_existing_values_and_allow_overrides(self):
        def app(environ, start_response):
            start_response("200 OK", [("X-Frame-Options", "SAMEORIGIN")])
            return [b"ok"]

        response, _, _ = invoke(
            SecurityHeadersMiddleware({
                "Referrer-Policy": "no-referrer",
                "X-Custom": "enabled",
            })(app)
        )
        headers = dict(response["headers"])
        self.assertEqual(headers["X-Frame-Options"], "SAMEORIGIN")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["X-Custom"], "enabled")

    def test_cors_preflight_and_origin_policy(self):
        def app(environ, start_response):
            start_response("200 OK", [])
            return [b"called"]

        middleware = CORSMiddleware(
            allowed_origins=("https://example.com",),
            methods=("GET", "POST"),
            headers=("X-Token",),
        )(app)
        response, body, _ = invoke(middleware, {
            "REQUEST_METHOD": "OPTIONS",
            "HTTP_ORIGIN": "https://example.com",
            "HTTP_ACCESS_CONTROL_REQUEST_METHOD": "POST",
            "HTTP_ACCESS_CONTROL_REQUEST_HEADERS": "X-Token",
        })
        self.assertEqual(response["status"], "204 No Content")
        self.assertEqual(body, b"")
        self.assertIn(
            ("Access-Control-Allow-Headers", "X-Token"),
            response["headers"],
        )

        response, _, _ = invoke(middleware, {
            "HTTP_ORIGIN": "https://not-allowed.example",
        })
        self.assertNotIn(
            "Access-Control-Allow-Origin",
            dict(response["headers"]),
        )

    def test_cors_rejects_credentialed_wildcard(self):
        with self.assertRaises(ValueError):
            CORSMiddleware(allowed_origins=("*",), allow_credentials=True)

    def test_gzip_streams_and_respects_minimum_size(self):
        payload = b"hello " * 200

        def app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [payload[:100], payload[100:]]

        response, body, _ = invoke(
            GZipMiddleware(minimum_size=10)(app),
            {"HTTP_ACCEPT_ENCODING": "gzip"},
        )
        self.assertEqual(gzip.decompress(body), payload)
        self.assertEqual(dict(response["headers"])["Content-Encoding"], "gzip")
        self.assertIn(("Vary", "Accept-Encoding"), response["headers"])

        response, body, _ = invoke(
            GZipMiddleware(minimum_size=10)(app),
            {"HTTP_ACCEPT_ENCODING": "gzip;q=0"},
        )
        self.assertEqual(body, payload)
        self.assertNotIn("Content-Encoding", dict(response["headers"]))

        response, body, _ = invoke(
            GZipMiddleware(minimum_size=10)(app),
            {"HTTP_ACCEPT_ENCODING": "*;q=1, gzip;q=0"},
        )
        self.assertEqual(body, payload)
        self.assertNotIn("Content-Encoding", dict(response["headers"]))

    def test_gzip_skips_small_responses_and_head(self):
        def app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"small"]

        response, body, _ = invoke(
            GZipMiddleware(minimum_size=10)(app),
            {"HTTP_ACCEPT_ENCODING": "gzip"},
        )
        self.assertEqual(body, b"small")
        self.assertNotIn("Content-Encoding", dict(response["headers"]))

        def no_transform_app(environ, start_response):
            start_response("200 OK", [
                ("Content-Type", "text/plain"),
                ("Cache-Control", "no-cache, no-transform"),
            ])
            return [b"response that should not be compressed"]

        response, body, _ = invoke(
            GZipMiddleware(minimum_size=1)(no_transform_app),
            {"HTTP_ACCEPT_ENCODING": "gzip"},
        )
        self.assertEqual(body, b"response that should not be compressed")
        self.assertNotIn("Content-Encoding", dict(response["headers"]))
        self.assertIn(("Vary", "Accept-Encoding"), response["headers"])

        response, body, _ = invoke(
            GZipMiddleware(minimum_size=1)(app),
            {"REQUEST_METHOD": "HEAD", "HTTP_ACCEPT_ENCODING": "gzip"},
        )
        self.assertEqual(body, b"small")
        self.assertNotIn("Content-Encoding", dict(response["headers"]))

    def test_rate_limit_is_per_client_and_returns_retry_after(self):
        @rate_limit(limit=1, window=30)
        def view(req):
            return "allowed"

        req = SimpleNamespace(environ={"REMOTE_ADDR": "192.0.2.1"})
        self.assertEqual(view(req), "allowed")
        status, headers, _ = view(req)
        self.assertEqual(status, "429 Too Many Requests")
        self.assertIn(("Retry-After", "30"), headers)
        self.assertEqual(
            view(SimpleNamespace(environ={"REMOTE_ADDR": "192.0.2.2"})),
            "allowed",
        )

    def test_pagination_and_flash_messages(self):
        page = paginate(list(range(7)), page="2", per_page=3)
        self.assertEqual(list(page.items), [3, 4, 5])
        self.assertEqual((page.total, page.pages), (7, 3))
        self.assertTrue(page.has_prev)
        self.assertTrue(page.has_next)
        self.assertEqual(paginate([], page=1).pages, 0)
        with self.assertRaises(ValueError):
            paginate([1], page=0)
        with self.assertRaises(ValueError):
            paginate([1], page=1.5)

        req = SimpleNamespace(session={})
        flash(req, "Saved", "success")
        flash(req, "Welcome")
        self.assertEqual(
            get_flashed_messages(
                req, category_filter=("success",), with_categories=True
            ),
            [("success", "Saved")],
        )
        self.assertEqual(get_flashed_messages(req), [])


if __name__ == "__main__":
    unittest.main()
