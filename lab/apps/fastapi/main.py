"""FastAPI lab app implementing the Labyrinth lab contract (see lab/README.md)."""
import asyncio
import secrets

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse

app = FastAPI()
SESSIONS: dict[str, str] = {}
ITEMS = [{"id": 1, "name": "Widget"}, {"id": 2, "name": "Gadget"}]


def user(request: Request):
    return SESSIONS.get(request.cookies.get("sid", ""))


@app.get("/api/health")
def health():
    return {"ok": True, "framework": "fastapi"}


@app.get("/api/items")
def items():
    return ITEMS


@app.get("/api/items/{iid}")
def item(iid: int):
    for it in ITEMS:
        if it["id"] == iid:
            return it
    raise HTTPException(404, "not found")


@app.post("/api/items", status_code=201)
async def create(request: Request):
    return {"id": 3, **(await request.json())}


@app.get("/login", response_class=HTMLResponse)
def login_form():
    return '<form method="post" action="/login"><input name="username"><input name="password" type="password"><button>Sign in</button></form>'


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username == "alice" and password == "wonderland":
        sid = secrets.token_hex(16)
        SESSIONS[sid] = "alice"
        r = RedirectResponse("/dashboard", status_code=302)
        r.set_cookie("sid", sid, httponly=True, samesite="lax")
        r.set_cookie("theme", "dark")
        return r
    return HTMLResponse("invalid credentials", status_code=401)


@app.get("/dashboard")
def dashboard(request: Request):
    u = user(request)
    return HTMLResponse(f"<h1>Welcome {u}</h1>") if u else RedirectResponse("/login", status_code=302)


@app.post("/checkout")
def checkout(request: Request):
    return {"ok": True, "order": 1001} if user(request) else JSONResponse({"error": "login required"}, 401)


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    return {"size": len(await file.read())}


@app.get("/redirect")
def redirect():
    return RedirectResponse("/api/health", status_code=302)


@app.get("/stream")
async def stream():
    async def gen():
        for n in range(1, 4):
            yield f"data: tick {n}\n\n"
            await asyncio.sleep(0.5)
    return StreamingResponse(gen(), media_type="text/event-stream")


@app.websocket("/ws")
async def ws(socket: WebSocket):
    await socket.accept()
    while True:
        await socket.send_text("echo:" + await socket.receive_text())
