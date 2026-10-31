"""Basic configurable CORS middleware."""

import re


_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_METHOD_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


def _replace_header(headers, name, value):
    lowered = name.lower()
    headers = [
        (key, item) for key, item in headers if key.lower() != lowered
    ]
    headers.append((name, value))
    return headers


def _add_vary(headers, value):
    for index, (name, current) in enumerate(headers):
        if name.lower() == "vary":
            if current.strip() == "*":
                return
            values = [item.strip() for item in current.split(",")]
            if value.lower() not in {item.lower() for item in values}:
                values.append(value)
            headers[index] = (name, ", ".join(values))
            return
    headers.append(("Vary", value))


class CORSMiddleware:
    """Apply an explicit cross-origin policy to a WSGI application."""

    def __init__(
        self,
        allowed_origins=(),
        allowed_methods=("GET", "HEAD", "POST", "OPTIONS"),
        allowed_headers=(),
        expose_headers=(),
        allow_credentials=False,
        max_age=600,
    ):
        self.allowed_origins = (
            (allowed_origins,) if isinstance(allowed_origins, str)
            else tuple(allowed_origins)
        )
        if any("\r" in origin or "\n" in origin for origin in self.allowed_origins):
            raise ValueError("Invalid CORS origin")
        if "*" in self.allowed_origins and allow_credentials:
            raise ValueError(
                "CORS credentials cannot be combined with a wildcard origin"
            )

        if isinstance(allowed_methods, str):
            allowed_methods = (allowed_methods,)
        self.allowed_methods = tuple(
            method.upper() for method in allowed_methods
        )
        if any(
            not _METHOD_NAME.fullmatch(method)
            for method in self.allowed_methods
        ):
            raise ValueError("Invalid CORS method")

        if isinstance(allowed_headers, str):
            allowed_headers = (allowed_headers,)
        self.allowed_headers = tuple(
            header.lower() for header in allowed_headers
        )
        if any(
            header != "*" and not _HEADER_NAME.fullmatch(header)
            for header in self.allowed_headers
        ):
            raise ValueError("Invalid CORS header name")

        if isinstance(expose_headers, str):
            expose_headers = (expose_headers,)
        self.expose_headers = tuple(expose_headers)
        if any(
            not _HEADER_NAME.fullmatch(header)
            for header in self.expose_headers
        ):
            raise ValueError("Invalid CORS exposed header name")

        if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0:
            raise ValueError("max_age must be a non-negative integer")
        self.allow_credentials = bool(allow_credentials)
        self.max_age = max_age

    def _allowed_origin(self, origin):
        if "*" in self.allowed_origins:
            return "*"
        if origin in self.allowed_origins:
            return origin
        return None

    def _cors_headers(self, origin):
        headers = [("Access-Control-Allow-Origin", origin)]
        if self.allow_credentials:
            headers.append(("Access-Control-Allow-Credentials", "true"))
        if self.expose_headers:
            headers.append((
                "Access-Control-Expose-Headers",
                ", ".join(self.expose_headers),
            ))
        if origin != "*":
            _add_vary(headers, "Origin")
        return headers

    def __call__(self, app):
        def middleware(environ, start_response):
            origin = environ.get("HTTP_ORIGIN")
            allowed_origin = self._allowed_origin(origin) if origin else None
            requested_method = environ.get(
                "HTTP_ACCESS_CONTROL_REQUEST_METHOD", ""
            ).upper()
            requested_headers = tuple(
                item.strip()
                for item in environ.get(
                    "HTTP_ACCESS_CONTROL_REQUEST_HEADERS", ""
                ).split(",")
                if item.strip()
            )
            valid_headers = all(
                _HEADER_NAME.fullmatch(header)
                for header in requested_headers
            )
            headers_allowed = valid_headers and (
                not requested_headers
                or "*" in self.allowed_headers
                or all(
                    header.lower() in self.allowed_headers
                    for header in requested_headers
                )
            )
            preflight = (
                environ.get("REQUEST_METHOD", "").upper() == "OPTIONS"
                and bool(requested_method)
            )

            if (
                preflight
                and allowed_origin
                and requested_method in self.allowed_methods
                and headers_allowed
            ):
                headers = self._cors_headers(allowed_origin)
                headers.append((
                    "Access-Control-Allow-Methods",
                    ", ".join(self.allowed_methods),
                ))
                if requested_headers:
                    headers.append((
                        "Access-Control-Allow-Headers",
                        ", ".join(requested_headers),
                    ))
                headers.append(("Access-Control-Max-Age", str(self.max_age)))
                _add_vary(headers, "Access-Control-Request-Method")
                _add_vary(headers, "Access-Control-Request-Headers")
                start_response("204 No Content", headers)
                return []

            def add_cors_headers(status, headers, exc_info=None):
                headers = list(headers)
                if allowed_origin:
                    cors_headers = self._cors_headers(allowed_origin)
                    for name, value in cors_headers:
                        if name.lower() == "vary":
                            _add_vary(headers, value)
                            continue
                        headers = _replace_header(headers, name, value)
                if exc_info is None:
                    return start_response(status, headers)
                return start_response(status, headers, exc_info)

            return app(environ, add_cors_headers)

        return middleware
