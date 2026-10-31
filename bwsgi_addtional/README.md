# Bwsgi Additional

Small, standard-library-only optional features for Bwsgi. Install with:

```bash
pip install bwsgi-additional
```

The add-on does not change Bwsgi's core dependencies. Its middleware follows
the WSGI callable interface and can be registered with `app.add_middleware`:

```python
from bwsgi_additional import (
    CORSMiddleware,
    GZipMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
)

app.add_middleware(CORSMiddleware(allowed_origins=("https://example.com",)))
app.add_middleware(GZipMiddleware())
app.add_middleware(RequestIDMiddleware())
app.add_middleware(SecurityHeadersMiddleware())
```

The package also provides a per-view in-memory rate limiter, flash messages
stored in Bwsgi's server-side session, and a sequence pagination helper:

```python
from bwsgi_additional import flash, get_flashed_messages, paginate, rate_limit

@app.route("/send")
@rate_limit(limit=30, window=60)
def send(req):
    flash(req, "Saved", category="success")
    return Response.redirect("/")

@app.route("/")
def home(req):
    notices = get_flashed_messages(req, with_categories=True)
    page = paginate(records, req.query.get("page", 1), per_page=20)
    return Response.json({"notices": notices, "items": list(page.items)})
```

`GZipMiddleware` compresses eligible response bodies as a stream when the
client accepts gzip. The rate limiter is process-local; use a shared store
behind a multi-process deployment if limits must be global.
