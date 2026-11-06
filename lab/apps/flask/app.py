"""Flask lab app implementing the Labyrinth lab contract (see lab/README.md). No websocket support."""
import time

from flask import Flask, Response, jsonify, redirect, request, session

app = Flask(__name__)
app.secret_key = "lab-only-not-a-secret"
ITEMS = [{"id": 1, "name": "Widget"}, {"id": 2, "name": "Gadget"}]


@app.get("/api/health")
def health():
    return {"ok": True, "framework": "flask"}


@app.get("/api/items")
def items():
    return jsonify(ITEMS)


@app.get("/api/items/<int:iid>")
def item(iid):
    for it in ITEMS:
        if it["id"] == iid:
            return it
    return {"error": "not found"}, 404


@app.post("/api/items")
def create():
    return {"id": 3, **request.get_json()}, 201


@app.get("/login")
def login_form():
    return '<form method="post" action="/login"><input name="username"><input name="password" type="password"><button>Sign in</button></form>'


@app.post("/login")
def login():
    if request.form.get("username") == "alice" and request.form.get("password") == "wonderland":
        session["user"] = "alice"
        r = redirect("/dashboard", code=302)
        r.set_cookie("theme", "dark")
        return r
    return "invalid credentials", 401


@app.get("/dashboard")
def dashboard():
    return f"<h1>Welcome {session['user']}</h1>" if session.get("user") else redirect("/login", code=302)


@app.post("/checkout")
def checkout():
    return ({"ok": True, "order": 1001}, 200) if session.get("user") else ({"error": "login required"}, 401)


@app.post("/upload")
def upload():
    f = request.files.get("file")
    return {"size": len(f.read()) if f else 0}


@app.get("/redirect")
def redir():
    return redirect("/api/health", code=302)


@app.get("/stream")
def stream():
    def gen():
        for n in range(1, 4):
            yield f"data: tick {n}\n\n"
            time.sleep(0.5)
    return Response(gen(), mimetype="text/event-stream")
