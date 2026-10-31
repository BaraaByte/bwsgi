import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from jinja2 import UndefinedError
from jinja2.exceptions import TemplateNotFound

from bwsgi import Bwsgi
from bwsgi_jinja import Jinja


class JinjaTests(unittest.TestCase):
    def test_register_uses_app_template_directory_and_renderer(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "hello.html").write_text("Hello {{ name }}", encoding="utf-8")
            app = Bwsgi(db_path=":memory:", template_dir=directory)
            extension = app.register(Jinja())
            self.assertIs(app.extensions["jinja"], extension)
            _, _, body = app.render_template("hello.html", name="Ada")
            self.assertEqual(b"".join(body), b"Hello Ada")

    def test_registers_renderer_with_autoescape_and_template_logic(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "home.html").write_text(
                "{% if user %}<h1>{{ user.name }}</h1>{% endif %}",
                encoding="utf-8",
            )
            app = SimpleNamespace(
                config={"TEMPLATE_DIR": directory, "DEBUG": False},
                extensions={},
                render_template=lambda *args, **kwargs: None,
            )
            extension = Jinja()
            extension.init_app(app)

            status, headers, body = app.render_template(
                "home.html", user={"name": "<Ada>"}
            )
            self.assertEqual(status, "200 OK")
            self.assertIn(("Content-Type", "text/html; charset=utf-8"), headers)
            self.assertEqual(b"".join(body), b"<h1>&lt;Ada&gt;</h1>")
            self.assertIs(app.extensions["jinja"], extension)

    def test_missing_values_and_templates_raise(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "home.html").write_text("{{ missing }}", encoding="utf-8")
            app = SimpleNamespace(
                config={"TEMPLATE_DIR": directory, "DEBUG": False},
                extensions={},
                render_template=lambda *args, **kwargs: None,
            )
            extension = Jinja()
            extension.init_app(app)
            with self.assertRaises(UndefinedError):
                extension.render_template("home.html")
            with self.assertRaises(TemplateNotFound):
                extension.render_template("../outside.html")


if __name__ == "__main__":
    unittest.main()
