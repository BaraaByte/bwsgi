"""Local dev server. Run: python run_local.py"""
import html
import sqlite3

from bwsgi import (
    Bwsgi, Response, csrf_protect, login_required,
    hash_password, verify_password, new_session_token, session_expiry,
)

app = Bwsgi(db_path="app.db", debug=True)


@app.route("/")
def home(req):
    return Response.html(
        "<h1>Welcome to Bwsgi</h1>"
        "<p><a href='/dashboard'>Dashboard</a> | "
        "<a href='/login'>Login</a> | "
        "<a href='/register'>Register</a></p>"
    )


@app.route("/login", methods=("GET", "POST"))
@csrf_protect
def login(req):
    if req.method == "GET":
        return Response.html(f"""
            <h1>Login</h1>
            <form method="post">
              <input name="username" placeholder="username" required><br>
              <input name="password" type="password" placeholder="password" required><br>
              <input type="hidden" name="_csrf_token" value="{req.csrf_token()}">
              <button type="submit">Login</button>
            </form>
            <p><a href='/register'>Register</a></p>
        """)

    data = req.form()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    row = app.db.fetchone(
        "SELECT id, password_hash, salt FROM users WHERE username = ?",
        (username,),
    )
    if not row or not verify_password(password, row["password_hash"], row["salt"]):
        return Response.html("<p>Invalid credentials.</p>", "401 Unauthorized")

    token = new_session_token()
    days = app.config["SESSION_DAYS"]
    app.db.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, row["id"], session_expiry(days)),
    )
    secure = "; Secure" if req.environ.get("wsgi.url_scheme") == "https" else ""
    cookie = (
        f"sessionid={token}; Path=/; HttpOnly; SameSite=Lax; "
        f"Max-Age={days * 86400}{secure}"
    )
    return Response.redirect("/dashboard", headers=[("Set-Cookie", cookie)])


@app.route("/register", methods=("GET", "POST"))
@csrf_protect
def register(req):
    if req.method == "GET":
        return Response.html(f"""
            <h1>Register</h1>
            <form method="post">
              <input name="username" placeholder="username" required><br>
              <input name="password" type="password" placeholder="password" required><br>
              <input type="hidden" name="_csrf_token" value="{req.csrf_token()}">
              <button type="submit">Create account</button>
            </form>
        """)

    data = req.form()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or len(password) < 8:
        return Response.html(
            "<p>Username required; password must be at least 8 chars.</p>",
            "400 Bad Request",
        )

    pwd_hash, salt = hash_password(password)
    try:
        app.db.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, pwd_hash, salt),
        )
    except sqlite3.IntegrityError:
        return Response.html("<p>Username taken.</p>", "409 Conflict")
    return Response.redirect("/login")


@app.route("/logout", methods=("POST",))
@csrf_protect
def logout(req):
    cookie = req.cookies.get("sessionid")
    if cookie:
        app.db.execute("DELETE FROM sessions WHERE token = ?", (cookie.value,))
    req.session.clear()
    secure = "; Secure" if req.environ.get("wsgi.url_scheme") == "https" else ""
    return Response.redirect("/", headers=[
        ("Set-Cookie", f"sessionid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{secure}")
    ])


@app.route("/dashboard")
@login_required
def dashboard(req):
    username = html.escape(req.user["username"])
    return Response.html(
        f"<h1>Welcome back, {username}</h1>"
        "<p>This is your secure area.</p>"
        f"<form method='post' action='/logout'>"
        f"<input type='hidden' name='_csrf_token' value='{req.csrf_token()}'>"
        "<button type='submit'>Logout</button></form>"
    )


@app.route("/api/me")
@login_required
def api_me(req):
    return Response.json({"id": req.user["id"], "username": req.user["username"]})


@app.errorhandler(404)
def not_found(req):
    return Response.html("<h1>404 - Page not found</h1>", "404 Not Found")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
