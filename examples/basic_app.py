"""Minimal Vinod app."""
from vinod import Vinod, Response

app = Vinod(db_path="example.db")

@app.route("/")
def index(req):
    return Response.html("<h1>Hello</h1>")

if __name__ == "__main__":
    app.run()
