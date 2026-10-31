"""Optional Jinja2 integration for Bwsgi."""

from pathlib import Path

from jinja2 import (
    Environment,
    FileSystemLoader,
    StrictUndefined,
    TemplateNotFound,
    select_autoescape,
)
from bwsgi import Response


class _TemplateRootLoader(FileSystemLoader):
    def get_source(self, environment, template):
        root = Path(self.searchpath[0]).resolve()
        candidate = (root / template).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise TemplateNotFound(template) from exc
        return super().get_source(environment, template)


class Jinja:
    """Install Jinja2 rendering as the app's ``render_template`` method."""

    def __init__(self, **environment_options):
        self.environment_options = environment_options
        self.environment = None
        self.app = None

    def init_app(self, app):
        self.app = app
        options = dict(self.environment_options)
        options.setdefault("autoescape", select_autoescape(("html", "htm", "xml")))
        options.setdefault("undefined", StrictUndefined)
        options.setdefault("auto_reload", bool(app.config.get("DEBUG")))
        options["loader"] = _TemplateRootLoader(
            str(Path(app.config["TEMPLATE_DIR"]).resolve())
        )
        self.environment = Environment(**options)
        app.extensions["jinja"] = self
        app.render_template = self.render_template

    def render_template(self, template_name, **context):
        """Render a template to Bwsgi's standard HTML response tuple."""
        if self.environment is None:
            raise RuntimeError("Register Jinja with an app before rendering")
        template = self.environment.get_template(template_name)
        return Response.html(template.render(**context))
