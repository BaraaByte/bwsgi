import unittest
from types import SimpleNamespace

from itsdangerous import BadSignature, SignatureExpired

from bwsgi import Bwsgi
from bwsgi_itsdangerous import ItsDangerous


class ItsDangerousTests(unittest.TestCase):
    def test_register_uses_app_secret_key(self):
        app = Bwsgi(db_path=":memory:", secret_key="test-secret")
        extension = app.register(ItsDangerous(salt="reset-password"))
        token = extension.dumps({"user_id": 42})
        self.assertEqual(extension.loads(token), {"user_id": 42})
        self.assertIs(app.extensions["itsdangerous"], extension)

    def test_registers_timed_url_safe_serializer(self):
        app = SimpleNamespace(
            config={"SECRET_KEY": "test-secret"},
            extensions={},
        )
        extension = ItsDangerous(salt="reset-password")
        extension.init_app(app)

        token = extension.dumps({"user_id": 42})
        self.assertEqual(extension.loads(token), {"user_id": 42})
        self.assertIs(app.extensions["itsdangerous"], extension)

        with self.assertRaises(BadSignature):
            extension.loads(token + "tampered")
        with self.assertRaises(SignatureExpired):
            extension.loads(token, max_age=-1)

    def test_custom_key_and_salt(self):
        app = SimpleNamespace(
            config={"SECRET_KEY": "app-secret"},
            extensions={},
        )
        extension = ItsDangerous(secret_key="token-secret", salt="email")
        extension.init_app(app)
        token = extension.dumps("verify")
        self.assertEqual(extension.loads(token), "verify")


if __name__ == "__main__":
    unittest.main()
