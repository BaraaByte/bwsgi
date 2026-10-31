"""Optional view decorators."""

from collections import OrderedDict
from functools import wraps
import threading
import time

from bwsgi import Response


def rate_limit(limit=60, window=60, key_func=None, max_clients=10_000):
    """Limit requests per client and view using an in-process fixed window."""
    if limit < 1 or window <= 0 or max_clients < 1:
        raise ValueError("limit, window, and max_clients must be positive")

    buckets = OrderedDict()
    lock = threading.Lock()
    last_prune = [0.0]

    def decorator(view):
        @wraps(view)
        def wrapper(req, *args, **kwargs):
            now = time.monotonic()
            client = (
                key_func(req) if key_func
                else req.environ.get("REMOTE_ADDR", "unknown")
            )
            key = str(client)
            with lock:
                if now - last_prune[0] >= window:
                    expired = [
                        item for item, (started, _) in buckets.items()
                        if now - started >= window
                    ]
                    for item in expired:
                        buckets.pop(item, None)
                    last_prune[0] = now

                started, count = buckets.get(key, (now, 0))
                if now - started >= window:
                    started, count = now, 0
                if count >= limit:
                    retry_after = max(1, int(window - (now - started) + 0.999))
                    return Response.text(
                        "Too Many Requests",
                        "429 Too Many Requests",
                        headers=[("Retry-After", str(retry_after))],
                    )

                buckets[key] = (started, count + 1)
                buckets.move_to_end(key)
                while len(buckets) > max_clients:
                    buckets.popitem(last=False)

            return view(req, *args, **kwargs)

        return wrapper

    return decorator
