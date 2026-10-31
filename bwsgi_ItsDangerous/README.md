# Bwsgi ItsDangerous

Optional signed payload support using ItsDangerous. Install only if your
application needs signed links or time-limited tokens:

```bash
pip install bwsgi-itsdangerous
```

```python
from bwsgi import Bwsgi
from bwsgi_itsdangerous import ItsDangerous

app = Bwsgi(secret_key="load-this-from-your-environment")
signing = app.register(ItsDangerous(salt="password-reset"))

token = signing.dumps({"user_id": 42})
payload = signing.loads(token, max_age=3600)
```

`loads` raises ItsDangerous' `BadSignature` or `SignatureExpired` for invalid
or expired tokens. The extension uses Bwsgi's configured secret key unless a
separate key is explicitly supplied.
