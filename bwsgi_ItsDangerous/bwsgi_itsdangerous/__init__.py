"""Optional ItsDangerous integration for Bwsgi."""

from itsdangerous import URLSafeTimedSerializer


class ItsDangerous:
    """Expose a URL-safe timed serializer through Bwsgi's extension registry."""

    def __init__(self, secret_key=None, salt="bwsgi", **serializer_options):
        self.secret_key = secret_key
        self.salt = salt
        self.serializer_options = serializer_options
        self.serializer = None

    def init_app(self, app):
        key = (
            app.config["SECRET_KEY"]
            if self.secret_key is None
            else self.secret_key
        )
        self.serializer = URLSafeTimedSerializer(
            key,
            salt=self.salt,
            **self.serializer_options,
        )
        app.extensions["itsdangerous"] = self

    def dumps(self, value, salt=None):
        """Serialize and sign a value as a URL-safe token."""
        if self.serializer is None:
            raise RuntimeError("Register ItsDangerous with an app before use")
        return self.serializer.dumps(value, salt=salt)

    def loads(self, token, max_age=None, salt=None):
        """Verify a token and optionally enforce its maximum age."""
        if self.serializer is None:
            raise RuntimeError("Register ItsDangerous with an app before use")
        return self.serializer.loads(token, max_age=max_age, salt=salt)
