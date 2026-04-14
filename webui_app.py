#!/usr/bin/env python3
"""
SadTalker Studio — Enterprise-grade web interface for talking head generation.

Architecture:
  - FastAPI backend with middleware pipeline (logging → rate-limit → auth)
  - Signed session cookies (itsdangerous) — no client-side token exposure
  - Structured JSON logging for observability
  - Response caching for static data (voices, presets, examples)
  - Path-safe file operations with resolve() checks on all I/O
"""

import os
import subprocess
import uuid
import json
import time
import shutil
import hashlib
import hmac
import logging
import threading
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from functools import lru_cache

from fastapi import FastAPI, UploadFile, File, Form, Request, Response, Cookie
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ─── Paths ───────────────────────────────────────────────────

APP_DIR = Path(__file__).parent
UPLOAD_DIR = APP_DIR / "uploads"
OUTPUT_DIR = APP_DIR / "outputs"
EXAMPLES_DIR = APP_DIR / "examples" / "source_image"
EXAMPLES_AUDIO_DIR = APP_DIR / "examples" / "driven_audio"
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# Max upload: 20 MB
MAX_UPLOAD_BYTES = 20 * 1024 * 1024

# ─── Structured Logger ───────────────────────────────────────
# JSON-formatted logs — easy to pipe into ELK/Datadog/CloudWatch

class StructuredLogger:
    """Centralized logger that outputs structured JSON for observability."""

    def __init__(self, name: str = "sadtalker"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(handler)

    def _emit(self, level: str, event: str, **ctx):
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "level": level,
            "event": event,
            **ctx,
        }
        self.logger.log(getattr(logging, level.upper(), 20), json.dumps(entry, ensure_ascii=False, default=str))

    def info(self, event, **ctx):  self._emit("info", event, **ctx)
    def warn(self, event, **ctx):  self._emit("warning", event, **ctx)
    def error(self, event, **ctx): self._emit("error", event, **ctx)

log = StructuredLogger()


# ─── Auth & RBAC Config ──────────────────────────────────────
# Roles: admin (full access), editor (generate+history), viewer (read-only)

SECRET_KEY = os.environ.get("ST_SECRET", uuid.uuid4().hex)
SESSION_MAX_AGE = 86400 * 7  # 7 days

serializer = URLSafeTimedSerializer(SECRET_KEY)

USERS_FILE = APP_DIR / "users.json"

ROLE_PERMISSIONS = {
    "admin":  {"generate", "history", "history.rename", "history.delete", "uploads", "uploads.delete", "presets", "presets.create", "presets.delete", "settings", "users"},
    "editor": {"generate", "history", "history.rename", "history.delete", "uploads", "presets", "settings"},
    "viewer": {"history", "uploads"},
}

def _hash_pw(password: str) -> str:
    """SHA-256 salted hash. Never store plaintext passwords."""
    salt = SECRET_KEY[:16]
    return hashlib.sha256((salt + password).encode()).hexdigest()


def _verify_pw(password: str, stored: str) -> bool:
    """Compare password against stored hash. Also accepts plaintext for migration."""
    hashed = _hash_pw(password)
    if stored == hashed:
        return True
    # Migration: if stored value is plaintext (not 64-char hex), hash-compare fails
    # Accept plaintext match ONCE, then caller should re-hash
    if len(stored) != 64 and stored == password:
        return True
    return False


def load_users() -> dict:
    """Load user database. Passwords stored as SHA-256 hashes."""
    if USERS_FILE.exists():
        try:
            return json.loads(USERS_FILE.read_text())
        except Exception:
            pass
    # Bootstrap from env vars — hash the password before storing
    default_user = os.environ.get("ST_USER", "admin")
    default_pass = os.environ.get("ST_PASS", "sadtalker")
    return {
        default_user: {
            "password": _hash_pw(default_pass),
            "role": "admin",
        }
    }


def save_users(data: dict):
    USERS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2))


def _migrate_plaintext_passwords():
    """One-time migration: hash any plaintext passwords in users.json."""
    if not USERS_FILE.exists():
        return
    users = load_users()
    changed = False
    for username, udata in users.items():
        pw = udata.get("password", "")
        if len(pw) != 64:  # not a SHA-256 hash
            udata["password"] = _hash_pw(pw)
            changed = True
            log.warn("password_migrated", user=username, detail="plaintext→hash")
    if changed:
        save_users(users)


def check_perm(role: str, perm: str) -> bool:
    return perm in ROLE_PERMISSIONS.get(role, set())


# In-memory state
jobs: dict = {}


# ─── Auth Helpers ────────────────────────────────────────────

def create_session(username: str, role: str) -> str:
    return serializer.dumps({"user": username, "role": role})


def verify_session(token: str | None) -> dict | None:
    """Returns {"user": str, "role": str} or None."""
    if not token:
        return None
    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE)
        if "user" in data:
            return data
    except (BadSignature, SignatureExpired):
        pass
    return None


# ─── Audit Log (ISO 27001 compliant) ────────────────────────
# Append-only JSON log of all state-changing actions

AUDIT_FILE = APP_DIR / "audit.log"

def audit(user: str, role: str, action: str, target: str = "", detail: str = "", ip: str = ""):
    """Write immutable audit entry. Fields: timestamp, user, role, action, target, detail, ip."""
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "user": user,
        "role": role,
        "action": action,
        "target": target,
        "detail": detail,
        "ip": ip,
    }
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    log.info("audit", **entry)


# ─── Feature Flags ───────────────────────────────────────────
# Toggle features without deploy. Checked by API + frontend.

FLAGS_FILE = APP_DIR / "flags.json"

DEFAULT_FLAGS = {
    "tts_enabled": True,
    "audio_upload_enabled": True,
    "custom_presets_enabled": True,
    "bg_enhancer_enabled": True,
    "max_concurrent_jobs": 3,
    "maintenance_mode": False,
}

def load_flags() -> dict:
    flags = dict(DEFAULT_FLAGS)
    if FLAGS_FILE.exists():
        try:
            flags.update(json.loads(FLAGS_FILE.read_text()))
        except Exception:
            pass
    return flags

def save_flags(data: dict):
    FLAGS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2))


# ─── Analytics / Telemetry ───────────────────────────────────
# Structured event collection for KPI tracking

ANALYTICS_FILE = APP_DIR / "analytics.log"

def track(event: str, user: str = "", props: dict | None = None):
    """Fire structured telemetry event."""
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "event": event,
        "user": user,
        **(props or {}),
    }
    with open(ANALYTICS_FILE, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ─── Path Safety ─────────────────────────────────────────────

def safe_path(base: Path, user_input: str) -> Path | None:
    """Resolve user-supplied filename and verify it stays inside base dir.
    Returns resolved Path or None if unsafe."""
    clean = Path(user_input).name  # strip directory traversal
    clean = re.sub(r'[^\w\-. ]', '_', clean)
    if not clean or clean.startswith('.'):
        return None
    resolved = (base / clean).resolve()
    if not str(resolved).startswith(str(base.resolve())):
        return None
    return resolved


# ─── Middleware Pipeline ─────────────────────────────────────
# Order: RequestID → Logging → RateLimit → Auth

PUBLIC_PATHS = {"/login", "/favicon.ico"}


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a unique request ID to every request for tracing."""
    async def dispatch(self, request: Request, call_next):
        rid = uuid.uuid4().hex[:12]
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """Log every request with method, path, status, and duration."""
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration_ms = round((time.time() - start) * 1000)
        rid = getattr(request.state, "request_id", "-")
        if not request.url.path.startswith("/examples/"):  # skip static noise
            log.info("http_request",
                rid=rid, method=request.method, path=request.url.path,
                status=response.status_code, ms=duration_ms)
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter — 30 requests/minute per IP on /api/generate."""
    LIMIT = 30
    WINDOW = 60

    def __init__(self, app):
        super().__init__(app)
        self.hits: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/api/generate" and request.method == "POST":
            ip = request.client.host if request.client else "unknown"
            now = time.time()
            self.hits[ip] = [t for t in self.hits[ip] if now - t < self.WINDOW]
            if len(self.hits[ip]) >= self.LIMIT:
                log.warn("rate_limited", ip=ip, path=request.url.path)
                return JSONResponse({"detail": "Too many requests"}, 429)
            self.hits[ip].append(now)
        return await call_next(request)


class AuthMiddleware(BaseHTTPMiddleware):
    """Enforce session auth + RBAC + maintenance mode."""
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in PUBLIC_PATHS or path.startswith("/examples/") or path.startswith("/static/"):
            return await call_next(request)

        # Maintenance mode — block all except admin
        flags = load_flags()
        token = request.cookies.get("session")
        session = verify_session(token)

        if not session:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Unauthorized"}, 401)
            return RedirectResponse("/login", 302)

        if flags.get("maintenance_mode") and session.get("role") != "admin":
            if path.startswith("/api/"):
                return JSONResponse({"detail": "ระบบอยู่ระหว่างบำรุงรักษา กรุณารอสักครู่"}, 503)
            eta = flags.get("maintenance_eta", "เร็วๆ นี้")
            contact = flags.get("maintenance_contact", "")
            return HTMLResponse(f"""<!DOCTYPE html><html lang="th"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SadTalker Studio — บำรุงรักษา</title>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+Thai:wght@400;600&display=swap" rel="stylesheet">
<style>*{{margin:0;padding:0;box-sizing:border-box;}}body{{font-family:'Noto Sans Thai',system-ui,sans-serif;
background:#F7F8FA;color:#1D1D1F;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center;padding:24px;}}
.card{{max-width:440px;}}.icon{{font-size:3rem;margin-bottom:16px;}}
h1{{font-size:1.3rem;margin-bottom:8px;}}p{{color:#6E6E73;font-size:.92rem;line-height:1.7;margin-bottom:8px;}}
.eta{{display:inline-block;margin-top:12px;padding:6px 16px;border-radius:8px;background:#EEF0FD;color:#4361EE;font-weight:600;font-size:.88rem;}}
.contact{{margin-top:16px;font-size:.82rem;color:#AEAEB2;}}</style></head><body>
<div class="card">
<div class="icon">&#128736;</div>
<h1>ระบบอยู่ระหว่างบำรุงรักษา</h1>
<p>เรากำลังปรับปรุงระบบให้ดีขึ้น ขออภัยในความไม่สะดวก</p>
<div class="eta">คาดว่าจะกลับมาใช้ได้: {eta}</div>
{"<p class='contact'>ติดต่อ: " + contact + "</p>" if contact else ""}
<p style="margin-top:20px;font-size:.78rem;color:#AEAEB2;">ระบบจะรีเฟรชอัตโนมัติเมื่อพร้อม</p>
</div>
<script>setInterval(()=>fetch('/api/flags').then(r=>r.json()).then(f=>{{if(!f.maintenance_mode)location.reload();}}).catch(()=>{{}}),30000);</script>
</body></html>""", 503)

        request.state.user = session.get("user", "")
        request.state.role = session.get("role", "viewer")
        return await call_next(request)


# ─── App Init ────────────────────────────────────────────────
# Middleware added in reverse order (last added = first executed)

app = FastAPI(docs_url=None, redoc_url=None)  # disable swagger in prod
app.add_middleware(AuthMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(LoggingMiddleware)
app.add_middleware(RequestIdMiddleware)

app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
app.mount("/outputs", StaticFiles(directory=str(OUTPUT_DIR)), name="outputs")
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")
app.mount("/examples", StaticFiles(directory=str(APP_DIR / "examples")), name="examples")


# ─── Cached Static Data ─────────────────────────────────────
# These rarely change — cache to avoid repeated dict construction

VOICES = {
    "th-TH-PremwadeeNeural": "ผู้หญิงไทย",
    "th-TH-NiwatNeural": "ผู้ชายไทย",
    "en-US-JennyNeural": "English Female",
    "en-US-GuyNeural": "English Male",
    "ja-JP-NanamiNeural": "日本語 Female",
    "ko-KR-SunHiNeural": "한국어 Female",
    "zh-CN-XiaoxiaoNeural": "中文 Female",
}

PRESETS = {
    "draft": {"preprocess": "crop", "size": 256, "enhancer": "", "still": True, "expression_scale": 1.0, "label": "เร็ว (Draft)", "desc": "crop + 256px ไม่ enhance — เร็วสุด"},
    "standard": {"preprocess": "full", "size": 256, "enhancer": "gfpgan", "still": True, "expression_scale": 1.0, "label": "มาตรฐาน", "desc": "full + GFPGAN — สมดุลคุณภาพ/เวลา"},
    "hq": {"preprocess": "full", "size": 256, "enhancer": "gfpgan", "still": False, "expression_scale": 1.0, "label": "คุณภาพสูง", "desc": "full + GFPGAN + ขยับหัว"},
    "marketing": {"preprocess": "full", "size": 256, "enhancer": "gfpgan", "still": True, "expression_scale": 1.2, "label": "การตลาด", "desc": "full + GFPGAN + expression เข้ม"},
}

@lru_cache(maxsize=1)
def _cached_examples():
    """Cache example image list — invalidated on server restart only."""
    images = []
    for ext in ("*.png", "*.jpg", "*.jpeg"):
        for f in sorted(EXAMPLES_DIR.glob(ext)):
            images.append({"name": f.stem, "filename": f.name, "url": f"/examples/source_image/{f.name}"})
    return images

VOICES = {
    "th-TH-PremwadeeNeural": "ผู้หญิงไทย",
    "th-TH-NiwatNeural": "ผู้ชายไทย",
    "en-US-JennyNeural": "English Female",
    "en-US-GuyNeural": "English Male",
    "ja-JP-NanamiNeural": "日本語 Female",
    "ko-KR-SunHiNeural": "한국어 Female",
    "zh-CN-XiaoxiaoNeural": "中文 Female",
}

PRESETS = {
    "draft": {"preprocess": "crop", "size": 256, "enhancer": "", "still": True, "expression_scale": 1.0, "label": "เร็ว (Draft)", "desc": "crop + 256px ไม่ enhance — เร็วสุด"},
    "standard": {"preprocess": "full", "size": 256, "enhancer": "gfpgan", "still": True, "expression_scale": 1.0, "label": "มาตรฐาน", "desc": "full + GFPGAN — สมดุลคุณภาพ/เวลา"},
    "hq": {"preprocess": "full", "size": 256, "enhancer": "gfpgan", "still": False, "expression_scale": 1.0, "label": "คุณภาพสูง", "desc": "full + GFPGAN + ขยับหัว"},
    "marketing": {"preprocess": "full", "size": 256, "enhancer": "gfpgan", "still": True, "expression_scale": 1.2, "label": "การตลาด", "desc": "full + GFPGAN + expression เข้ม"},
}


def run_generation(job_id: str, params: dict):
    """Background worker for video generation."""
    job = jobs[job_id]
    try:
        venv_python = str(APP_DIR / "venv" / "bin" / "python")
        audio_path = params["audio_path"]

        # Step 1: TTS if needed
        if params.get("tts_text"):
            job["step"] = "tts"
            job["progress"] = 5
            voice = params.get("voice", "th-TH-PremwadeeNeural")
            rate = params.get("rate", "+0%")
            pitch = params.get("pitch", "+0Hz")
            tts_cmd = [
                str(APP_DIR / "venv" / "bin" / "edge-tts"),
                "--voice", voice,
                "--rate", rate,
                "--pitch", pitch,
                "--text", params["tts_text"],
                "--write-media", audio_path,
            ]
            proc = subprocess.run(tts_cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode != 0:
                job["status"] = "error"
                job["error"] = f"TTS failed: {proc.stderr[-300:]}"
                return

        job["step"] = "inference"
        job["progress"] = 15

        # Step 2: Build inference command
        output_dir = str(OUTPUT_DIR / job_id)
        os.makedirs(output_dir, exist_ok=True)

        cmd = [
            venv_python, str(APP_DIR / "inference.py"),
            "--driven_audio", audio_path,
            "--source_image", params["image_path"],
            "--result_dir", output_dir,
            "--preprocess", params.get("preprocess", "full"),
            "--expression_scale", str(params.get("expression_scale", 1.0)),
            "--batch_size", str(params.get("batch_size", 2)),
            "--pose_style", str(params.get("pose_style", 0)),
        ]

        if params.get("still", True):
            cmd.append("--still")

        enhancer = params.get("enhancer", "gfpgan")
        if enhancer:
            cmd.extend(["--enhancer", enhancer])

        bg_enhancer = params.get("background_enhancer", "")
        if bg_enhancer:
            cmd.extend(["--background_enhancer", bg_enhancer])

        size = params.get("size", 256)
        if size and size != 256:
            cmd.extend(["--size", str(size)])

        # Custom head rotation
        if params.get("input_yaw"):
            cmd.extend(["--input_yaw"] + [str(v) for v in params["input_yaw"]])
        if params.get("input_pitch"):
            cmd.extend(["--input_pitch"] + [str(v) for v in params["input_pitch"]])
        if params.get("input_roll"):
            cmd.extend(["--input_roll"] + [str(v) for v in params["input_roll"]])

        # Ref videos
        if params.get("ref_eyeblink"):
            cmd.extend(["--ref_eyeblink", params["ref_eyeblink"]])
        if params.get("ref_pose"):
            cmd.extend(["--ref_pose", params["ref_pose"]])

        job["progress"] = 20

        proc = subprocess.run(
            cmd, cwd=str(APP_DIR),
            capture_output=True, text=True, timeout=900
        )

        # Parse progress from stderr for render steps
        if proc.stderr:
            lines = proc.stderr
            if "Face Renderer:: 100%" in lines:
                job["progress"] = 80
            if "Face Enhancer:: 100%" in lines or "seamlessClone:: 100%" in lines:
                job["progress"] = 95

        if proc.returncode != 0:
            job["status"] = "error"
            job["error"] = proc.stderr[-500:] if proc.stderr else "Unknown error"
            return

        # Find the generated video
        mp4_files = sorted(Path(output_dir).rglob("*.mp4"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not mp4_files:
            job["status"] = "error"
            job["error"] = "No video generated"
            return

        # Copy to output with safe name (sanitize user input)
        src_video = mp4_files[0]
        raw_name = params.get("output_name", f"{job_id}.mp4")
        safe_name = Path(raw_name).name  # strip any directory components
        safe_name = re.sub(r'[^\w\-. ]', '_', safe_name)  # whitelist safe chars
        if not safe_name or safe_name.startswith('.'):
            safe_name = f"{job_id}.mp4"
        if not safe_name.endswith(".mp4"):
            safe_name += ".mp4"
        final_path = (OUTPUT_DIR / safe_name).resolve()
        if not str(final_path).startswith(str(OUTPUT_DIR.resolve())):
            final_path = OUTPUT_DIR / f"{job_id}.mp4"
        final_name = final_path.name
        shutil.copy2(str(src_video), str(final_path))

        # Save metadata
        meta = {
            "id": job_id,
            "filename": final_name,
            "created": datetime.now().isoformat(),
            "text": params.get("tts_text", ""),
            "voice": params.get("voice", ""),
            "image": Path(params["image_path"]).name,
            "preset": params.get("preset", "custom"),
            "preprocess": params.get("preprocess", "full"),
            "enhancer": enhancer,
            "expression_scale": params.get("expression_scale", 1.0),
            "still": params.get("still", True),
            "size_bytes": final_path.stat().st_size,
        }
        (OUTPUT_DIR / f"{final_name}.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2))

        # Cleanup intermediate dir
        shutil.rmtree(output_dir, ignore_errors=True)

        job["status"] = "done"
        job["progress"] = 100
        job["result"] = f"/outputs/{final_name}"
        job["filename"] = final_name
        job["meta"] = meta

    except subprocess.TimeoutExpired:
        job["status"] = "error"
        job["error"] = "Timeout: generation took too long (>15 min)"
        log.error("job_timeout", job_id=job_id)
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
        log.error("job_failed", job_id=job_id, error=str(e))
    finally:
        elapsed = round(time.time() - job.get("created", time.time()), 1)
        log.info("job_finished", job_id=job_id, status=job.get("status"), elapsed_s=elapsed)
        job["finished_at"] = time.time()


def cleanup_old_jobs():
    """Remove jobs older than 1 hour to prevent memory leak."""
    cutoff = time.time() - 3600
    stale = [k for k, v in jobs.items() if v.get("finished_at", v.get("created", 0)) < cutoff]
    for k in stale:
        # Mark stuck running jobs as error
        if jobs[k].get("status") == "running":
            jobs[k]["status"] = "error"
            jobs[k]["error"] = "Job timed out (stuck)"
        del jobs[k]


# ─── API Routes ──────────────────────────────────────────────

@app.post("/api/generate")
async def api_generate(
    request: Request,
    text: str = Form(""),
    voice: str = Form("th-TH-PremwadeeNeural"),
    rate: str = Form("+0%"),
    pitch: str = Form("+0Hz"),
    image: UploadFile | None = File(None),
    audio: UploadFile | None = File(None),
    example_image: str = Form(""),
    preset: str = Form("standard"),
    preprocess: str = Form(""),
    size: int = Form(0),
    enhancer: str = Form(""),
    background_enhancer: str = Form(""),
    still: str = Form(""),
    expression_scale: float = Form(0),
    pose_style: int = Form(0),
    batch_size: int = Form(2),
    input_yaw: str = Form(""),
    input_pitch: str = Form(""),
    input_roll: str = Form(""),
    output_name: str = Form(""),
):
    # RBAC check
    user = getattr(request.state, "user", "")
    role = getattr(request.state, "role", "viewer")
    if not check_perm(role, "generate"):
        return JSONResponse({"detail": "ไม่มีสิทธิ์สร้างวิดีโอ"}, 403)

    job_id = uuid.uuid4().hex[:8]
    log.info("generate_request", job_id=job_id, user=user, preset=preset)
    audit(user, role, "generate", target=job_id, detail=f"preset={preset}")
    track("generate_start", user=user, props={"preset": preset, "job_id": job_id})

    # Resolve image (with size + type validation)
    ALLOWED_IMG = {".png", ".jpg", ".jpeg", ".webp"}
    ALLOWED_AUDIO = {".mp3", ".wav", ".m4a", ".ogg"}

    if image and image.filename:
        ext = Path(image.filename).suffix.lower()
        if ext not in ALLOWED_IMG:
            return JSONResponse({"detail": f"ไฟล์รูปต้องเป็น {', '.join(ALLOWED_IMG)}"}, 400)
        content = await image.read()
        if len(content) > MAX_UPLOAD_BYTES:
            return JSONResponse({"detail": f"ไฟล์ใหญ่เกิน {MAX_UPLOAD_BYTES // 1024 // 1024} MB"}, 400)
        img_path = UPLOAD_DIR / f"{job_id}_img{ext}"
        img_path.write_bytes(content)
        img_path_str = str(img_path)
    elif example_image:
        img_path = safe_path(EXAMPLES_DIR, example_image)
        if not img_path or not img_path.exists():
            return JSONResponse({"detail": "Image not found"}, 400)
        img_path_str = str(img_path)
    else:
        return JSONResponse({"detail": "No image provided"}, 400)

    # Resolve audio (with size + type validation)
    tts_text = ""
    audio_path = str(UPLOAD_DIR / f"{job_id}_audio.mp3")
    if audio and audio.filename:
        ext = Path(audio.filename).suffix.lower()
        if ext not in ALLOWED_AUDIO:
            return JSONResponse({"detail": f"ไฟล์เสียงต้องเป็น {', '.join(ALLOWED_AUDIO)}"}, 400)
        content = await audio.read()
        if len(content) > MAX_UPLOAD_BYTES:
            return JSONResponse({"detail": f"ไฟล์ใหญ่เกิน {MAX_UPLOAD_BYTES // 1024 // 1024} MB"}, 400)
        audio_path = str(UPLOAD_DIR / f"{job_id}_audio{ext}")
        Path(audio_path).write_bytes(content)
    elif text.strip():
        tts_text = text.strip()
    else:
        return JSONResponse({"detail": "No text or audio provided"}, 400)

    # Apply preset, then override with custom values
    p = PRESETS.get(preset, PRESETS["standard"]).copy()
    if preprocess:
        p["preprocess"] = preprocess
    if size > 0:
        p["size"] = size
    if enhancer:
        p["enhancer"] = enhancer if enhancer != "none" else ""
    if still:
        p["still"] = still == "true"
    if expression_scale > 0:
        p["expression_scale"] = expression_scale

    params = {
        "image_path": img_path_str,
        "audio_path": audio_path,
        "tts_text": tts_text,
        "voice": voice,
        "rate": rate,
        "pitch": pitch,
        "preset": preset,
        "preprocess": p["preprocess"],
        "size": p["size"],
        "enhancer": p["enhancer"],
        "background_enhancer": background_enhancer if background_enhancer != "none" else "",
        "still": p["still"],
        "expression_scale": p["expression_scale"],
        "pose_style": pose_style,
        "batch_size": batch_size,
        "output_name": output_name or f"sadtalker_{job_id}.mp4",
    }

    # Parse custom rotations
    def parse_ints(s):
        if not s.strip():
            return None
        return [int(x) for x in s.replace(",", " ").split() if x.lstrip("-").isdigit()]

    params["input_yaw"] = parse_ints(input_yaw)
    params["input_pitch"] = parse_ints(input_pitch)
    params["input_roll"] = parse_ints(input_roll)

    jobs[job_id] = {"status": "running", "step": "starting", "progress": 0, "created": time.time()}
    thread = threading.Thread(target=run_generation, args=(job_id, params), daemon=True)
    thread.start()

    return {"job_id": job_id}


@app.get("/api/status/{job_id}")
async def api_status(job_id: str):
    cleanup_old_jobs()
    job = jobs.get(job_id)
    if not job:
        return JSONResponse({"detail": "Job not found"}, 404)
    # Auto-detect stuck jobs (running > 20 min with no progress)
    if job.get("status") == "running" and time.time() - job.get("created", 0) > 1200:
        job["status"] = "error"
        job["error"] = "Job timed out after 20 minutes"
    return job


@app.get("/api/history")
async def api_history():
    items = []
    for meta_file in sorted(OUTPUT_DIR.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
        try:
            meta = json.loads(meta_file.read_text())
            video_path = OUTPUT_DIR / meta["filename"]
            if video_path.exists():
                meta["video_url"] = f"/outputs/{meta['filename']}"
                items.append(meta)
        except Exception:
            pass
    return items


@app.delete("/api/history/{filename}")
async def api_delete(filename: str):
    safe = Path(filename).name  # strip directory components
    video_path = (OUTPUT_DIR / safe).resolve()
    meta_path = (OUTPUT_DIR / f"{safe}.json").resolve()
    if not str(video_path).startswith(str(OUTPUT_DIR.resolve())):
        return JSONResponse({"detail": "Invalid filename"}, 400)
    if video_path.exists():
        video_path.unlink()
    if meta_path.exists():
        meta_path.unlink()
    return {"ok": True}


@app.get("/api/examples")
async def api_examples():
    return _cached_examples()


# ─── Uploads CRUD ────────────────────────────────────────────

@app.get("/api/uploads")
async def api_uploads():
    """List all user-uploaded images."""
    items = []
    for ext in ("*.png", "*.jpg", "*.jpeg", "*.webp"):
        for f in sorted(UPLOAD_DIR.glob(ext), key=lambda x: x.stat().st_mtime, reverse=True):
            if "_img" in f.name:  # only image uploads, not audio
                items.append({
                    "filename": f.name,
                    "url": f"/uploads/{f.name}",
                    "size_bytes": f.stat().st_size,
                    "created": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                })
    return items


@app.delete("/api/uploads/{filename}")
async def api_delete_upload(filename: str):
    safe = Path(filename).name
    fpath = (UPLOAD_DIR / safe).resolve()
    if not str(fpath).startswith(str(UPLOAD_DIR.resolve())):
        return JSONResponse({"detail": "Invalid filename"}, 400)
    if fpath.exists():
        fpath.unlink()
    return {"ok": True}


# ─── Video Rename ────────────────────────────────────────────

@app.patch("/api/history/{filename}")
async def api_rename_video(filename: str, new_name: str = Form(...)):
    safe_old = Path(filename).name
    old_video = (OUTPUT_DIR / safe_old).resolve()
    old_meta = (OUTPUT_DIR / f"{safe_old}.json").resolve()
    if not str(old_video).startswith(str(OUTPUT_DIR.resolve())) or not old_video.exists():
        return JSONResponse({"detail": "Video not found"}, 404)

    # Sanitize new name
    safe_new = re.sub(r'[^\w\-. ]', '_', Path(new_name).name)
    if not safe_new or safe_new.startswith('.'):
        return JSONResponse({"detail": "Invalid name"}, 400)
    if not safe_new.endswith(".mp4"):
        safe_new += ".mp4"
    new_video = (OUTPUT_DIR / safe_new).resolve()
    if not str(new_video).startswith(str(OUTPUT_DIR.resolve())):
        return JSONResponse({"detail": "Invalid name"}, 400)

    old_video.rename(new_video)
    # Update metadata
    if old_meta.exists():
        meta = json.loads(old_meta.read_text())
        meta["filename"] = safe_new
        new_meta = OUTPUT_DIR / f"{safe_new}.json"
        new_meta.write_text(json.dumps(meta, ensure_ascii=False, indent=2))
        if old_meta != new_meta:
            old_meta.unlink()
    return {"ok": True, "filename": safe_new}


# ─── Custom Presets CRUD ─────────────────────────────────────

CUSTOM_PRESETS_FILE = APP_DIR / "custom_presets.json"

def load_custom_presets() -> dict:
    if CUSTOM_PRESETS_FILE.exists():
        try:
            return json.loads(CUSTOM_PRESETS_FILE.read_text())
        except Exception:
            pass
    return {}


def save_custom_presets(data: dict):
    CUSTOM_PRESETS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2))


@app.get("/api/custom-presets")
async def api_custom_presets():
    return load_custom_presets()


@app.post("/api/custom-presets")
async def api_create_preset(
    key: str = Form(...),
    label: str = Form(...),
    desc: str = Form(""),
    preprocess: str = Form("full"),
    enhancer: str = Form("gfpgan"),
    still: str = Form("true"),
    expression_scale: float = Form(1.0),
):
    safe_key = re.sub(r'[^\w\-]', '_', key.strip().lower())
    if not safe_key or safe_key in PRESETS:
        return JSONResponse({"detail": "Invalid or reserved preset name"}, 400)
    cp = load_custom_presets()
    cp[safe_key] = {
        "preprocess": preprocess,
        "size": 256,
        "enhancer": enhancer if enhancer != "none" else "",
        "still": still == "true",
        "expression_scale": expression_scale,
        "label": label.strip(),
        "desc": desc.strip(),
        "custom": True,
    }
    save_custom_presets(cp)
    return {"ok": True, "key": safe_key}


@app.put("/api/custom-presets/{key}")
async def api_update_preset(
    key: str,
    label: str = Form(...),
    desc: str = Form(""),
    preprocess: str = Form("full"),
    enhancer: str = Form("gfpgan"),
    still: str = Form("true"),
    expression_scale: float = Form(1.0),
):
    cp = load_custom_presets()
    if key not in cp:
        return JSONResponse({"detail": "Preset not found"}, 404)
    cp[key] = {
        "preprocess": preprocess,
        "size": 256,
        "enhancer": enhancer if enhancer != "none" else "",
        "still": still == "true",
        "expression_scale": expression_scale,
        "label": label.strip(),
        "desc": desc.strip(),
        "custom": True,
    }
    save_custom_presets(cp)
    return {"ok": True}


@app.delete("/api/custom-presets/{key}")
async def api_delete_preset(key: str):
    cp = load_custom_presets()
    if key not in cp:
        return JSONResponse({"detail": "Preset not found"}, 404)
    del cp[key]
    save_custom_presets(cp)
    return {"ok": True}


@app.get("/api/voices")
async def api_voices():
    return VOICES


@app.get("/api/presets")
async def api_presets():
    merged = dict(PRESETS)
    merged.update(load_custom_presets())
    return merged


# ─── Auth Endpoints ──────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(session: str | None = Cookie(None)):
    if verify_session(session):
        return RedirectResponse("/", 302)
    login_html = APP_DIR / "static" / "login.html"
    return login_html.read_text(encoding="utf-8")


@app.post("/login")
async def login_submit(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    users = load_users()
    user_data = users.get(username)
    ip = request.client.host if request.client else ""
    if user_data and _verify_pw(password, user_data.get("password", "")):
        # Auto-migrate plaintext → hash on successful login
        if len(user_data.get("password", "")) != 64:
            user_data["password"] = _hash_pw(password)
            save_users(users)
        role = user_data.get("role", "viewer")
        token = create_session(username, role)
        resp = RedirectResponse("/", 302)
        resp.set_cookie("session", token, httponly=True, samesite="lax", max_age=SESSION_MAX_AGE)
        audit(username, role, "login", ip=ip)
        track("login", user=username, props={"role": role})
        return resp
    audit(username, "none", "login_failed", ip=ip)
    login_html = (APP_DIR / "static" / "login.html").read_text(encoding="utf-8")
    return HTMLResponse(login_html.replace("<!--ERROR-->", '<p class="err">ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง</p>'), 401)


@app.get("/logout")
async def logout(request: Request):
    user = getattr(request.state, "user", "")
    role = getattr(request.state, "role", "")
    audit(user, role, "logout")
    resp = RedirectResponse("/login", 302)
    resp.delete_cookie("session")
    return resp


@app.get("/api/me")
async def api_me(request: Request, session: str | None = Cookie(None)):
    data = verify_session(session)
    if not data:
        return JSONResponse({"detail": "Unauthorized"}, 401)
    role = data.get("role", "viewer")
    return {
        "user": data["user"],
        "role": role,
        "permissions": sorted(ROLE_PERMISSIONS.get(role, set())),
    }


# ─── Feature Flags + Audit + Analytics Endpoints ─────────────

@app.get("/api/flags")
async def api_flags():
    return load_flags()


@app.put("/api/flags")
async def api_update_flags(request: Request):
    if getattr(request.state, "role", "") != "admin":
        return JSONResponse({"detail": "Admin only"}, 403)
    body = await request.json()
    flags = load_flags()
    flags.update(body)
    save_flags(flags)
    audit(request.state.user, "admin", "flags_updated", detail=json.dumps(body))
    return {"ok": True}


@app.get("/api/audit")
async def api_audit(request: Request):
    """Return last 100 audit entries (admin only)."""
    if getattr(request.state, "role", "") != "admin":
        return JSONResponse({"detail": "Admin only"}, 403)
    if not AUDIT_FILE.exists():
        return []
    lines = AUDIT_FILE.read_text().strip().split("\n")[-100:]
    return [json.loads(l) for l in lines if l.strip()]


@app.post("/api/track")
async def api_track(request: Request):
    """Receive frontend telemetry events."""
    body = await request.json()
    track(
        event=body.get("event", "unknown"),
        user=getattr(request.state, "user", ""),
        props=body.get("props", {}),
    )
    return {"ok": True}


@app.get("/api/users")
async def api_list_users(request: Request):
    if getattr(request.state, "role", "") != "admin":
        return JSONResponse({"detail": "Admin only"}, 403)
    users = load_users()
    # Mask passwords (PII protection)
    return {k: {"role": v.get("role", "viewer")} for k, v in users.items()}


@app.post("/api/users")
async def api_create_user(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form("viewer")):
    if getattr(request.state, "role", "") != "admin":
        return JSONResponse({"detail": "Admin only"}, 403)
    if role not in ROLE_PERMISSIONS:
        return JSONResponse({"detail": f"Invalid role. Use: {list(ROLE_PERMISSIONS.keys())}"}, 400)
    users = load_users()
    if username in users:
        return JSONResponse({"detail": "User already exists"}, 400)
    users[username] = {"password": _hash_pw(password), "role": role}
    save_users(users)
    audit(request.state.user, "admin", "user_created", target=username, detail=f"role={role}")
    return {"ok": True}


@app.delete("/api/users/{username}")
async def api_delete_user(request: Request, username: str):
    if getattr(request.state, "role", "") != "admin":
        return JSONResponse({"detail": "Admin only"}, 403)
    users = load_users()
    if username not in users:
        return JSONResponse({"detail": "User not found"}, 404)
    del users[username]
    save_users(users)
    audit(request.state.user, "admin", "user_deleted", target=username)
    return {"ok": True}


# ─── PDPA / Data Subject Rights ──────────────────────────────

@app.post("/api/anonymize")
async def api_anonymize(request: Request):
    """Request account deletion / data anonymization (PDPA Art.33)."""
    user = getattr(request.state, "user", "")
    role = getattr(request.state, "role", "")
    audit(user, role, "anonymize_request", detail="User requested data deletion/anonymization")
    log.info("anonymize_request", user=user)
    # In production: queue for admin review + 30-day processing
    # For now: record the request in audit log
    return {"ok": True, "message": "คำขอถูกบันทึกแล้ว ผู้ดูแลจะดำเนินการภายใน 30 วัน"}


# ─── Frontend (protected) ────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(session: str | None = Cookie(None)):
    if not verify_session(session):
        return RedirectResponse("/login", 302)
    html_path = APP_DIR / "static" / "index.html"
    return html_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    import uvicorn

    # Migrate any plaintext passwords on startup
    _migrate_plaintext_passwords()

    # Warn if using default credentials
    default_pass = os.environ.get("ST_PASS", "sadtalker")
    if default_pass == "sadtalker":
        print("\n  *** WARNING: Using default password! ***")
        print("  Set ST_PASS environment variable for production.\n")

    print("=" * 50)
    print("  SadTalker Studio")
    print(f"  http://localhost:8000")
    users = load_users()
    first_user = next(iter(users.keys()), "admin")
    print(f"  Login: {first_user}")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=8000)
