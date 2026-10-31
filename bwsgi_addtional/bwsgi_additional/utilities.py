"""Lightweight helpers for session messages and sequence pagination."""

from dataclasses import dataclass
from math import ceil
from typing import Generic, Optional, Sequence, TypeVar


T = TypeVar("T")
_FLASH_KEY = "_bwsgi_flash_messages"


@dataclass(frozen=True)
class Page(Generic[T]):
    """A slice of a sequence and its pagination metadata."""

    items: Sequence[T]
    page: int
    per_page: int
    total: int
    pages: int

    @property
    def has_next(self):
        return self.page < self.pages

    @property
    def has_prev(self):
        return self.page > 1 and self.pages > 0

    @property
    def next_page(self) -> Optional[int]:
        return self.page + 1 if self.has_next else None

    @property
    def prev_page(self) -> Optional[int]:
        return self.page - 1 if self.has_prev else None


def paginate(items: Sequence[T], page=1, per_page=20) -> Page[T]:
    """Return one page of a sequence; out-of-range pages contain no items."""
    if isinstance(page, bool) or isinstance(per_page, bool):
        raise ValueError("page and per_page must be integers")
    if isinstance(page, float) and not page.is_integer():
        raise ValueError("page and per_page must be integers")
    if isinstance(per_page, float) and not per_page.is_integer():
        raise ValueError("page and per_page must be integers")
    try:
        page = int(page)
        per_page = int(per_page)
    except (TypeError, ValueError) as exc:
        raise ValueError("page and per_page must be integers") from exc
    if page < 1 or per_page < 1:
        raise ValueError("page and per_page must be positive")

    total = len(items)
    pages = ceil(total / per_page)
    start = (page - 1) * per_page
    return Page(items[start:start + per_page], page, per_page, total, pages)


def flash(req, message, category="message"):
    """Queue a one-time message in the current Bwsgi session."""
    messages = req.session.setdefault(_FLASH_KEY, [])
    messages.append((str(category), str(message)))


def get_flashed_messages(req, category_filter=None, with_categories=False):
    """Consume queued messages, optionally filtering by category."""
    messages = req.session.pop(_FLASH_KEY, [])
    if not isinstance(messages, list):
        raise ValueError("Stored flash messages must be a list")
    if isinstance(category_filter, str):
        allowed = {category_filter}
    else:
        allowed = set(category_filter) if category_filter is not None else None
    selected = [
        (category, message)
        for category, message in messages
        if allowed is None or category in allowed
    ]
    if with_categories:
        return selected
    return [message for _, message in selected]
