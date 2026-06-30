"""
GitHub 推送管理平台 V3 — 银行级安全
FastAPI + Vue3/Vant4 + SQLite
"""
import os, json, hmac, hashlib, time, uuid, re, sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
import httpx
import bcrypt
import jwt

# ── Config ──────────────────────────────────
BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "data" / "guardian.db"
JWT_SECRET = os.environ.get("GUARDIAN_JWT_SECRET", "guardian-v3-secret-change-me")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MIN = 60
RATE_LIMIT_RPM = 100
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "wh-secret-change-me")

os.makedirs(BASE_DIR / "data", exist_ok=True)

app = FastAPI(title="GitHub Push Guardian", version="3.0", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-RateLimit-Remaining"],
)

# ── DB ──────────────────────────────────────
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            path TEXT,
            type TEXT DEFAULT 'code',
            remote_url TEXT NOT NULL,
            branch TEXT DEFAULT 'main',
            auto_push INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS remotes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            ip_address TEXT,
            trace_id TEXT,
            timestamp TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(timestamp);
        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            delivery_id TEXT UNIQUE NOT NULL,
            event_type TEXT NOT NULL,
            repo TEXT,
            branch TEXT,
            forced INTEGER DEFAULT 0,
            commit_count INTEGER,
            payload TEXT,
            received_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS policy_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            conditions TEXT NOT NULL,  -- JSON array
            action TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS push_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            action TEXT,
            message TEXT,
            status TEXT,
            detail TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    # Create default admin if none
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        pw = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?,?)", ("admin", pw))
    conn.commit()
    conn.close()

init_db()

# ── Rate Limiter ────────────────────────────
_rate_store: dict = {}

def rate_limit(limit: int = RATE_LIMIT_RPM):
    async def middleware(request: Request):
        ip = request.client.host if request.client else "unknown"
        key = f"rl:{ip}"
        now = time.time()
        window = _rate_store.get(key, {"start": now, "count": 0})
        if now - window["start"] > 60:
            window = {"start": now, "count": 0}
        window["count"] += 1
        _rate_store[key] = window
        if window["count"] > limit:
            raise HTTPException(429, detail="Too Many Requests")
    return middleware

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        await rate_limit(RATE_LIMIT_RPM)(request)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# ── Auth ────────────────────────────────────
def create_token(user_id: int, username: str) -> str:
    return jwt.encode({
        "sub": str(user_id),
        "username": username,
        "jti": uuid.uuid4().hex,
        "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MIN),
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

def get_current_user(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    return verify_token(auth[7:])

# ── Audit ───────────────────────────────────
def audit_log(action: str, user_id: int = None, resource_type: str = None,
              resource_id: str = None, details: str = None, ip: str = None):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address, trace_id) VALUES (?,?,?,?,?,?,?)",
            (user_id, action, resource_type, resource_id, details, ip, uuid.uuid4().hex[:12])
        )
        conn.commit()
    finally:
        conn.close()

# ── API: Auth ───────────────────────────────
class LoginReq(BaseModel):
    username: str
    password: str

@app.post("/api/auth/login")
async def login(req: LoginReq, request: Request):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (req.username,)).fetchone()
    conn.close()
    if not user or not bcrypt.checkpw(req.password.encode(), user["password_hash"].encode()):
        raise HTTPException(401, "Invalid credentials")
    token = create_token(user["id"], user["username"])
    audit_log("login", user["id"], "user", str(user["id"]), ip=request.client.host)
    return {"token": token, "user": {"id": user["id"], "username": user["username"], "role": user["role"]}}

@app.get("/api/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {"user": user}

# ── API: Projects ───────────────────────────
@app.get("/api/projects")
async def list_projects():
    conn = get_db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM projects ORDER BY updated_at DESC").fetchall()]
    conn.close()
    return {"projects": rows}

class ProjectCreate(BaseModel):
    name: str
    path: str = ""
    remote_url: str
    branch: str = "main"
    type: str = "code"

@app.post("/api/projects")
async def add_project(p: ProjectCreate, user: dict = Depends(get_current_user), request: Request = None):
    conn = get_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur = conn.execute(
        "INSERT INTO projects (name, path, type, remote_url, branch, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
        (p.name, p.path, p.type, p.remote_url, p.branch, now, now)
    )
    conn.commit()
    pid = cur.lastrowid
    conn.execute("INSERT INTO push_logs (project_id, action, message, status, created_at) VALUES (?,?,?,?,?)",
                 (pid, "add", f"添加项目: {p.name}", "ok", now))
    conn.commit()
    conn.close()
    audit_log("project_add", user_id=int(user["sub"]), resource_type="project", resource_id=str(pid),
              ip=request.client.host if request else None)
    return {"ok": True, "id": pid}

@app.delete("/api/projects/{pid}")
async def del_project(pid: int, user: dict = Depends(get_current_user), request: Request = None):
    conn = get_db()
    conn.execute("DELETE FROM projects WHERE id=?", (pid,))
    conn.commit()
    conn.close()
    audit_log("project_delete", user_id=int(user["sub"]), resource_type="project", resource_id=str(pid),
              ip=request.client.host if request else None)
    return {"ok": True}

class ProjectUpdate(BaseModel):
    name: str = None
    path: str = None
    remote_url: str = None
    branch: str = None
    type: str = None

@app.put("/api/projects/{pid}")
async def update_project(pid: int, p: ProjectUpdate, user: dict = Depends(get_current_user), request: Request = None):
    conn = get_db()
    existing = conn.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(404, "项目不存在")
    sets = []
    vals = []
    for k in ["name", "path", "remote_url", "branch", "type"]:
        v = getattr(p, k, None)
        if v is not None:
            sets.append(f"{k}=?")
            vals.append(v)
    if sets:
        vals.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        sets.append("updated_at=?")
        conn.execute(f"UPDATE projects SET {','.join(sets)} WHERE id=?", vals + [pid])
        conn.commit()
    conn.close()
    audit_log("project_update", user_id=int(user["sub"]), resource_type="project", resource_id=str(pid),
              ip=request.client.host if request else None)
    return {"ok": True}

# ── API: Git Push ───────────────────────────
class PushReq(BaseModel):
    project_id: int
    message: str = "auto push"

@app.post("/api/git/push")
async def git_push(req: PushReq, user: dict = Depends(get_current_user), request: Request = None):
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id=?", (req.project_id,)).fetchone()
    conn.close()
    if not proj:
        raise HTTPException(404, "Project not found")

    import subprocess, shlex
    cmd = f"cd {shlex.quote(proj['path'])} && git add . && git commit -m {shlex.quote(req.message)} && git push origin {shlex.quote(proj['branch'])} 2>&1"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
    status = "ok" if result.returncode == 0 else "error"
    detail = (result.stdout + result.stderr)[:2000]

    conn = get_db()
    conn.execute(
        "INSERT INTO push_logs (project_id, action, message, status, detail, created_at) VALUES (?,?,?,?,?,?)",
        (req.project_id, "push", req.message, status, detail, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.execute("UPDATE projects SET updated_at=? WHERE id=?", 
                 (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), req.project_id))
    conn.commit()
    conn.close()
    audit_log("git_push", user_id=int(user["sub"]), resource_type="project", resource_id=str(req.project_id),
              details=req.message, ip=request.client.host if request else None)
    return {"ok": status == "ok", "status": status, "output": detail}

# ── API: Webhook ────────────────────────────
@app.api_route("/api/webhook/github", methods=["POST"])
async def github_webhook(request: Request):
    signature = request.headers.get("x-hub-signature-256", "")
    delivery_id = request.headers.get("x-github-delivery", "")
    event_type = request.headers.get("x-github-event", "unknown")

    body = await request.body()
    payload_str = body.decode()

    # 1. Verify signature
    if WEBHOOK_SECRET:
        computed = "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, computed):
            audit_log("webhook_invalid_sig", resource_type="webhook", details=delivery_id)
            raise HTTPException(403, "Invalid signature")

    # 2. Dedup
    conn = get_db()
    existing = conn.execute("SELECT id FROM webhook_events WHERE delivery_id=?", (delivery_id,)).fetchone()
    if existing:
        conn.close()
        return {"status": "duplicate"}

    # 3. Store
    payload = json.loads(payload_str) if payload_str else {}
    repo = payload.get("repository", {}).get("full_name", "")
    ref = payload.get("ref", "")
    branch = ref.replace("refs/heads/", "") if ref.startswith("refs/heads/") else ref
    forced = payload.get("forced", False)
    commits = payload.get("commits", [])
    commit_count = len(commits)

    conn.execute(
        "INSERT INTO webhook_events (delivery_id, event_type, repo, branch, forced, commit_count, payload) VALUES (?,?,?,?,?,?,?)",
        (delivery_id, event_type, repo, branch, int(forced), commit_count, payload_str)
    )
    conn.commit()

    # 4. Policy check
    rules = conn.execute("SELECT * FROM policy_rules WHERE enabled=1").fetchall()
    hits = []
    for rule in rules:
        conditions = json.loads(rule["conditions"])
        if _match_conditions(conditions, {"branch": branch, "forced": forced, "commit_count": commit_count, "repo": repo}):
            hits.append({"rule_id": rule["id"], "name": rule["name"], "action": rule["action"]})

    conn.execute("INSERT INTO push_logs (action, message, status, detail, created_at) VALUES (?,?,?,?,?)",
                 ("webhook", f"{event_type} on {repo}", "ok", json.dumps({"delivery_id": delivery_id, "hits": hits}),
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

    audit_log("webhook_received", resource_type="webhook", resource_id=delivery_id, 
              details=f"{event_type} {repo} {branch}")

    return {"status": "accepted", "hits": hits}

# ── Policy Engine ───────────────────────────
def _match_conditions(conditions: list, event: dict) -> bool:
    for cond in conditions:
        t = cond.get("type", "")
        if t == "branch_match":
            if not re.search(cond.get("pattern", ""), event.get("branch", "")):
                return False
        elif t == "force_push":
            if bool(event.get("forced")) != bool(cond.get("value", False)):
                return False
        elif t == "commit_count_max":
            if event.get("commit_count", 0) <= cond.get("max", 999):
                return False
    return True

# ── API: Policies ───────────────────────────
@app.get("/api/policies")
async def list_policies():
    conn = get_db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM policy_rules ORDER BY id").fetchall()]
    for r in rows:
        r["conditions"] = json.loads(r["conditions"])
    conn.close()
    return {"policies": rows}

class PolicyCreate(BaseModel):
    name: str
    conditions: list
    action: str
    enabled: bool = True

@app.post("/api/policies")
async def add_policy(p: PolicyCreate, user: dict = Depends(get_current_user)):
    conn = get_db()
    conn.execute(
        "INSERT INTO policy_rules (name, enabled, conditions, action) VALUES (?,?,?,?)",
        (p.name, int(p.enabled), json.dumps(p.conditions), p.action)
    )
    conn.commit()
    conn.close()
    audit_log("policy_add", user_id=int(user["sub"]), resource_type="policy", details=p.name)
    return {"ok": True}

@app.put("/api/policies/{pid}")
async def toggle_policy(pid: int, user: dict = Depends(get_current_user)):
    conn = get_db()
    rule = conn.execute("SELECT enabled FROM policy_rules WHERE id=?", (pid,)).fetchone()
    if not rule:
        conn.close()
        raise HTTPException(404)
    new_state = 0 if rule["enabled"] else 1
    conn.execute("UPDATE policy_rules SET enabled=? WHERE id=?", (new_state, pid))
    conn.commit()
    conn.close()
    return {"ok": True, "enabled": bool(new_state)}

@app.delete("/api/policies/{pid}")
async def del_policy(pid: int, user: dict = Depends(get_current_user)):
    conn = get_db()
    conn.execute("DELETE FROM policy_rules WHERE id=?", (pid,))
    conn.commit()
    conn.close()
    audit_log("policy_delete", user_id=int(user["sub"]), resource_type="policy", resource_id=str(pid))
    return {"ok": True}

# ── API: Audit Logs ─────────────────────────
@app.get("/api/audit")
async def list_audit(limit: int = 50, offset: int = 0):
    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?", (limit, offset)
    ).fetchall()]
    total = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    conn.close()
    return {"logs": rows, "total": total}

# ── API: Logs ───────────────────────────────
@app.get("/api/logs")
async def list_logs(limit: int = 50, offset: int = 0):
    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM push_logs ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)
    ).fetchall()]
    total = conn.execute("SELECT COUNT(*) FROM push_logs").fetchone()[0]
    conn.close()
    return {"logs": rows, "total": total}

# ── API: Remotes ────────────────────────────
@app.get("/api/remotes")
async def list_remotes():
    conn = get_db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM remotes ORDER BY id").fetchall()]
    conn.close()
    return {"remotes": rows}

class RemoteCreate(BaseModel):
    name: str
    url: str

@app.post("/api/remotes")
async def add_remote(r: RemoteCreate):
    conn = get_db()
    conn.execute("INSERT INTO remotes (name, url) VALUES (?,?)", (r.name, r.url))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.delete("/api/remotes/{rid}")
async def del_remote(rid: int):
    conn = get_db()
    conn.execute("DELETE FROM remotes WHERE id=?", (rid,))
    conn.commit()
    conn.close()
    return {"ok": True}

# ── API: Self Status ────────────────────────
@app.get("/api/self")
async def self_status():
    import subprocess
    try:
        r = subprocess.run(["git", "branch", "--show-current"], capture_output=True, text=True, cwd=BASE_DIR.parent, timeout=5)
        branch = r.stdout.strip()
        r2 = subprocess.run(["git", "remote", "-v"], capture_output=True, text=True, cwd=BASE_DIR.parent, timeout=5)
        remotes_count = len([l for l in r2.stdout.strip().split("\n") if "(fetch)" in l])
        r3 = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, cwd=BASE_DIR.parent, timeout=5)
        changed = len([l for l in r3.stdout.strip().split("\n") if l])
        return {"branch": branch, "remotes_count": remotes_count, "changed_files": changed}
    except:
        return {"branch": "?", "remotes_count": 0, "changed_files": 0}

@app.post("/api/self/push-all")
async def push_all(user: dict = Depends(get_current_user)):
    import subprocess
    remotes = get_db().execute("SELECT * FROM remotes").fetchall()
    results = []
    for r in remotes:
        cmd = f"cd {BASE_DIR.parent} && git push {r['name']} main 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        results.append({"name": r["name"], "ok": result.returncode == 0, "output": (result.stdout + result.stderr)[:500]})
    get_db().close()
    return {"results": results}

# ── Static + SPA ────────────────────────────
STATIC_DIR = BASE_DIR / "static"

@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/{path:path}")
async def serve_static(path: str):
    fp = STATIC_DIR / path
    if fp.is_file():
        return FileResponse(fp)
    return FileResponse(STATIC_DIR / "index.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8010)
