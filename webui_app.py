#!/usr/bin/env python3
"""SadTalker Web UI — Full-featured browser interface with authentication."""

import os
import subprocess
import uuid
import json
import time
import shutil
import hashlib
import hmac
import threading
import re
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, Form, Request, Response, Cookie
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

APP_DIR = Path(__file__).parent
UPLOAD_DIR = APP_DIR / "uploads"
OUTPUT_DIR = APP_DIR / "outputs"
EXAMPLES_DIR = APP_DIR / "examples" / "source_image"
EXAMPLES_AUDIO_DIR = APP_DIR / "examples" / "driven_audio"
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# ─── Auth Config ─────────────────────────────────────────────
# Set via environment variables or .env file
ADMIN_USER = os.environ.get("ST_USER", "admin")
ADMIN_PASS = os.environ.get("ST_PASS", "sadtalker")
SECRET_KEY = os.environ.get("ST_SECRET", uuid.uuid4().hex)
SESSION_MAX_AGE = 86400 * 7  # 7 days

serializer = URLSafeTimedSerializer(SECRET_KEY)

# Track running jobs
jobs: dict = {}


# ─── Auth Helpers ────────────────────────────────────────────

def create_session(username: str) -> str:
    return serializer.dumps({"user": username})


def verify_session(token: str | None) -> str | None:
    if not token:
        return None
    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE)
        return data.get("user")
    except (BadSignature, SignatureExpired):
        return None


from starlette.middleware.base import BaseHTTPMiddleware

PUBLIC_PATHS = {"/login", "/favicon.ico"}

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in PUBLIC_PATHS or path.startswith("/examples/"):
            return await call_next(request)
        token = request.cookies.get("session")
        if not verify_session(token):
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Unauthorized"}, 401)
            return RedirectResponse("/login", 302)
        return await call_next(request)


app = FastAPI()
app.add_middleware(AuthMiddleware)

app.mount("/outputs", StaticFiles(directory=str(OUTPUT_DIR)), name="outputs")
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")
app.mount("/examples", StaticFiles(directory=str(APP_DIR / "examples")), name="examples")

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
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
    finally:
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
    job_id = uuid.uuid4().hex[:8]

    # Resolve image
    if image and image.filename:
        ext = Path(image.filename).suffix or ".png"
        img_path = UPLOAD_DIR / f"{job_id}_img{ext}"
        img_path.write_bytes(await image.read())
        img_path_str = str(img_path)
    elif example_image:
        safe_img = Path(example_image).name  # strip directory components
        img_path = (EXAMPLES_DIR / safe_img).resolve()
        if not str(img_path).startswith(str(EXAMPLES_DIR.resolve())) or not img_path.exists():
            return JSONResponse({"detail": f"Image not found: {safe_img}"}, 400)
        img_path_str = str(img_path)
    else:
        return JSONResponse({"detail": "No image provided"}, 400)

    # Resolve audio
    tts_text = ""
    audio_path = str(UPLOAD_DIR / f"{job_id}_audio.mp3")
    if audio and audio.filename:
        ext = Path(audio.filename).suffix or ".mp3"
        audio_path = str(UPLOAD_DIR / f"{job_id}_audio{ext}")
        Path(audio_path).write_bytes(await audio.read())
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
    images = []
    for ext in ("*.png", "*.jpg", "*.jpeg"):
        for f in sorted(EXAMPLES_DIR.glob(ext)):
            images.append({"name": f.stem, "filename": f.name, "url": f"/examples/source_image/{f.name}"})
    return images


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
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    if username == ADMIN_USER and password == ADMIN_PASS:
        token = create_session(username)
        resp = RedirectResponse("/", 302)
        resp.set_cookie("session", token, httponly=True, samesite="lax", max_age=SESSION_MAX_AGE)
        return resp
    login_html = (APP_DIR / "static" / "login.html").read_text(encoding="utf-8")
    return HTMLResponse(login_html.replace("<!--ERROR-->", '<p class="err">ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง</p>'), 401)


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", 302)
    resp.delete_cookie("session")
    return resp


@app.get("/api/me")
async def api_me(session: str | None = Cookie(None)):
    user = verify_session(session)
    if not user:
        return JSONResponse({"detail": "Unauthorized"}, 401)
    return {"user": user}


# ─── Frontend (protected) ────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(session: str | None = Cookie(None)):
    if not verify_session(session):
        return RedirectResponse("/login", 302)
    html_path = APP_DIR / "static" / "index.html"
    return html_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    import uvicorn
    print("=" * 50)
    print("  SadTalker Studio")
    print(f"  http://localhost:8000")
    print(f"  Login: {ADMIN_USER} / {ADMIN_PASS}")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=8000)
