"""Optional, standard-library-only features for Bwsgi."""

from .decorators import rate_limit
from .middleware import (
    CORSMiddleware,
    GZipMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
)
from .utilities import Page, flash, get_flashed_messages, paginate

__all__ = [
    "CORSMiddleware",
    "GZipMiddleware",
    "Page",
    "RequestIDMiddleware",
    "SecurityHeadersMiddleware",
    "flash",
    "get_flashed_messages",
    "paginate",
    "rate_limit",
]
