"""Optional WSGI middleware for Bwsgi."""

from collections import deque
import re
import uuid
import zlib


def _replace_header(headers, name, value):
    lowered = name.lower()
    result = [(key, item) for key, item in headers if key.lower() != lowered]
    result.append((name, value))
    return result


def _add_vary(headers, value):
    for index, (name, current) in enumerate(headers):
        if name.lower() == "vary":
            if current.strip() == "*":
                return headers
            values = [item.strip() for item in current.split(",")]
            if value.lower() not in {item.lower() for item in values}:
                values.append(value)
            headers[index] = (name, ", ".join(values))
            return headers
    headers.append(("Vary", value))
    return headers


def _accepts_gzip(value):
    encodings = {}
    for encoding in value.split(","):
        parts = [part.strip() for part in encoding.split(";")]
        name = parts[0].lower()
        if not name:
            continue
        quality = 1.0
        for parameter in parts[1:]:
            key, separator, item = parameter.partition("=")
            if separator and key.strip().lower() == "q":
                try:
                    quality = float(item)
                except ValueError:
                    quality = 0.0
                break
        encodings[name] = quality if 0 <= quality <= 1 else 0.0
    return encodings.get("gzip", encodings.get("*", 0.0)) > 0


def _merge_headers(headers, additional):
    for name, value in additional:
        headers = _replace_header(headers, name, value)
    return headers


class RequestIDMiddleware:
    """Assign a request ID and include it in the response headers."""

    def __init__(self, header="X-Request-ID", environ_key="bwsgi.request_id"):
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", header):
            raise ValueError("header must be a valid HTTP header name")
        self.header = header
        self.environ_key = environ_key

    def __call__(self, app):
        header_key = "HTTP_" + self.header.upper().replace("-", "_")

        def middleware(environ, start_response):
            request_id = environ.get(header_key, "")
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", request_id):
                request_id = uuid.uuid4().hex
            environ[self.environ_key] = request_id

            def add_header(status, headers, exc_info=None):
                return start_response(
                    status,
                    _replace_header(headers, self.header, request_id),
                    exc_info,
                )

            return app(environ, add_header)

        return middleware


class SecurityHeadersMiddleware:
    """Add conservative browser security headers unless already set."""

    DEFAULT_HEADERS = (
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
    )

    def __init__(self, headers=None):
        self.headers = list(self.DEFAULT_HEADERS)
        if headers:
            for name, value in headers.items():
                if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                    raise ValueError("Invalid response header name")
                if any(char in str(value) for char in "\r\n"):
                    raise ValueError("Invalid response header value")
                self.headers = _replace_header(
                    self.headers, name, str(value)
                )

    def __call__(self, app):
        def middleware(environ, start_response):
            def add_headers(status, headers, exc_info=None):
                present = {name.lower() for name, _ in headers}
                headers = list(headers)
                headers.extend(
                    (name, value) for name, value in self.headers
                    if name.lower() not in present
                )
                return start_response(status, headers, exc_info)

            return app(environ, add_headers)

        return middleware


class CORSMiddleware:
    """Apply an explicit CORS policy and handle valid preflight requests."""

    def __init__(
        self,
        allowed_origins=(),
        methods=("GET", "HEAD", "POST", "OPTIONS"),
        headers=(),
        expose_headers=(),
        allow_credentials=False,
        max_age=600,
    ):
        self.allowed_origins = (
            (allowed_origins,) if isinstance(allowed_origins, str)
            else tuple(allowed_origins)
        )
        if "*" in self.allowed_origins and allow_credentials:
            raise ValueError("CORS credentials cannot be combined with '*'")
        methods = (methods,) if isinstance(methods, str) else methods
        headers = (headers,) if isinstance(headers, str) else headers
        expose_headers = (
            (expose_headers,) if isinstance(expose_headers, str)
            else expose_headers
        )
        self.methods = tuple(method.upper() for method in methods)
        self.headers = tuple(header.lower() for header in headers)
        self.expose_headers = tuple(expose_headers)
        if any("\r" in origin or "\n" in origin for origin in self.allowed_origins):
            raise ValueError("Invalid allowed origin")
        for header in self.headers + tuple(
            header.lower() for header in self.expose_headers
        ):
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", header):
                raise ValueError("Invalid CORS header name")
        if any(
            not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method)
            for method in self.methods
        ):
            raise ValueError("Invalid CORS method")
        self.allow_credentials = allow_credentials
        if max_age < 0:
            raise ValueError("max_age must be non-negative")
        self.max_age = max_age

    def _allowed_origin(self, origin):
        if "*" in self.allowed_origins:
            return "*"
        return origin if origin in self.allowed_origins else None

    def _cors_headers(self, origin, requested_headers=()):
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
        if requested_headers:
            headers.append((
                "Access-Control-Allow-Headers",
                ", ".join(requested_headers),
            ))
        return headers

    def __call__(self, app):
        def middleware(environ, start_response):
            origin = environ.get("HTTP_ORIGIN")
            allowed_origin = self._allowed_origin(origin) if origin else None
            requested_method = environ.get(
                "HTTP_ACCESS_CONTROL_REQUEST_METHOD", ""
            ).upper()
            requested_headers = tuple(
                value.strip()
                for value in environ.get(
                    "HTTP_ACCESS_CONTROL_REQUEST_HEADERS", ""
                ).split(",")
                if value.strip()
            )
            invalid_requested_headers = any(
                not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", header)
                for header in requested_headers
            )
            is_preflight = (
                environ.get("REQUEST_METHOD", "").upper() == "OPTIONS"
                and bool(requested_method)
            )
            headers_allowed = not invalid_requested_headers and (
                not requested_headers
                or "*" in self.headers
                or all(
                    header.lower() in self.headers
                    for header in requested_headers
                )
            )

            if (
                is_preflight
                and allowed_origin
                and requested_method in self.methods
                and headers_allowed
            ):
                headers = self._cors_headers(allowed_origin, requested_headers)
                headers.extend([
                    ("Access-Control-Allow-Methods", ", ".join(self.methods)),
                    ("Access-Control-Max-Age", str(self.max_age)),
                ])
                _add_vary(headers, "Access-Control-Request-Method")
                _add_vary(headers, "Access-Control-Request-Headers")
                start_response("204 No Content", headers)
                return []

            def add_headers(status, response_headers, exc_info=None):
                response_headers = list(response_headers)
                if allowed_origin:
                    response_headers = _merge_headers(
                        response_headers, self._cors_headers(allowed_origin)
                    )
                return start_response(status, response_headers, exc_info)

            return app(environ, add_headers)

        return middleware


class GZipMiddleware:
    """Stream gzip-compressed eligible responses without buffering the body."""

    _COMPRESSIBLE_TYPES = (
        "text/",
        "application/json",
        "application/javascript",
        "application/xml",
        "image/svg+xml",
    )

    def __init__(self, minimum_size=500):
        if minimum_size < 0:
            raise ValueError("minimum_size must be non-negative")
        self.minimum_size = minimum_size

    def __call__(self, app):
        def middleware(environ, start_response):
            response = {}
            writes = deque()

            def capture(status, headers, exc_info=None):
                response["status"] = status
                response["headers"] = list(headers)
                return writes.append

            iterable = app(environ, capture)
            if "status" not in response:
                close = getattr(iterable, "close", None)
                if close:
                    close()
                raise RuntimeError("WSGI application did not call start_response")

            status = response["status"]
            headers = response["headers"]
            header_map = {name.lower(): value for name, value in headers}
            content_type = header_map.get("content-type", "").lower()
            status_code = int(status.split(" ", 1)[0])
            accepts_gzip = _accepts_gzip(
                environ.get("HTTP_ACCEPT_ENCODING", "")
            )
            can_have_body = status_code >= 200 and status_code not in {
                204, 206, 304,
            }
            content_is_compressible = (
                content_type.startswith(self._COMPRESSIBLE_TYPES)
                and "content-encoding" not in header_map
            )
            if content_is_compressible:
                _add_vary(headers, "Accept-Encoding")
            no_transform = any(
                directive.strip().split("=", 1)[0].lower() == "no-transform"
                for directive in header_map.get("cache-control", "").split(",")
            )
            eligible = (
                accepts_gzip
                and can_have_body
                and environ.get("REQUEST_METHOD", "").upper() != "HEAD"
                and not no_transform
                and content_is_compressible
            )

            def output():
                source = iter(iterable)
                pending_size = 0
                pending = []
                compressor = None
                response_started = False

                def start_plain():
                    nonlocal response_started
                    if not response_started:
                        start_response(status, headers)
                        response_started = True

                def start_compressed():
                    nonlocal response_started
                    compressed_headers = [
                        (name, value) for name, value in headers
                        if name.lower() != "content-length"
                    ]
                    compressed_headers = _replace_header(
                        compressed_headers, "Content-Encoding", "gzip"
                    )
                    _add_vary(compressed_headers, "Accept-Encoding")
                    start_response(status, compressed_headers)
                    response_started = True

                def write_chunk(chunk):
                    nonlocal compressor
                    if compressor is None:
                        return chunk
                    return compressor.compress(chunk)

                try:
                    if not eligible:
                        start_plain()
                        while writes:
                            yield writes.popleft()
                        for chunk in source:
                            while writes:
                                yield writes.popleft()
                            yield chunk
                        while writes:
                            yield writes.popleft()
                        return

                    while True:
                        if writes:
                            chunk = writes.popleft()
                        else:
                            try:
                                chunk = next(source)
                            except StopIteration:
                                break
                            while writes:
                                pending.append(writes.popleft())
                                pending_size += len(pending[-1])
                        pending.append(chunk)
                        pending_size += len(chunk)
                        if pending_size >= self.minimum_size:
                            compressor = zlib.compressobj(
                                wbits=16 + zlib.MAX_WBITS
                            )
                            start_compressed()
                            for buffered in pending:
                                compressed = write_chunk(buffered)
                                if compressed:
                                    yield compressed
                            pending.clear()
                            break

                    if compressor is None:
                        start_plain()
                        yield from pending
                        pending.clear()
                        while writes:
                            yield writes.popleft()
                        for chunk in source:
                            while writes:
                                yield writes.popleft()
                            yield chunk
                        while writes:
                            yield writes.popleft()
                        return

                    while writes:
                        compressed = write_chunk(writes.popleft())
                        if compressed:
                            yield compressed
                    for chunk in source:
                        while writes:
                            compressed = write_chunk(writes.popleft())
                            if compressed:
                                yield compressed
                        compressed = write_chunk(chunk)
                        if compressed:
                            yield compressed
                    while writes:
                        compressed = write_chunk(writes.popleft())
                        if compressed:
                            yield compressed
                    tail = compressor.flush()
                    if tail:
                        yield tail
                finally:
                    close = getattr(iterable, "close", None)
                    if close:
                        close()

            return output()

        return middleware
