# Bwsgi Jinja

Optional Jinja2 integration. The base `bwsgi` package remains zero-dependency.

```bash
pip install bwsgi-jinja
```

Register the extension to replace Bwsgi's lightweight variable-substitution
renderer with Jinja2 while keeping the familiar `app.render_template` API:

```python
from bwsgi import Bwsgi
from bwsgi_jinja import Jinja

app = Bwsgi(template_dir="templates", secret_key="load-from-environment")
app.register(Jinja())

@app.route("/")
def home(req):
    return app.render_template("home.html", user={"name": "Ada"})
```

HTML/XML templates are autoescaped, undefined values raise an error, and the
configured `TEMPLATE_DIR` remains the template root. Jinja2 syntax, includes,
inheritance, filters, and macros are available.
