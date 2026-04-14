# SadTalker Studio

Generate talking head videos from a single face image + text. Type what you want the face to say, pick a voice, and get a lip-synced MP4.

Built on [SadTalker](https://github.com/OpenTalker/SadTalker) (CVPR 2023) with a full-featured web UI.

## Architecture

```
Browser (vanilla JS)          FastAPI Backend              SadTalker Engine
┌─────────────────┐     ┌──────────────────────┐     ┌──────────────────┐
│  Login Page      │────▶│  Auth Middleware      │     │  inference.py    │
│  Studio UI       │     │  Rate Limiter         │     │  3DMM Extraction │
│  - Create video  │◀───▶│  Structured Logger    │────▶│  Face Renderer   │
│  - History       │     │  Request ID Tracing   │     │  GFPGAN Enhance  │
│  - Uploads       │     │  API Endpoints        │     │  Video Compose   │
│  - Presets       │     │  Job Queue (threads)   │     └──────────────────┘
│  - Guide         │     │  File I/O (safe_path) │
└─────────────────┘     └──────────────────────┘
                              │
                        Edge TTS (Microsoft)
                        Text → Speech → MP3
```

**Key design decisions:**
- **Single-file backend** (`webui_app.py`, ~650 lines) — no framework bloat
- **Vanilla JS frontend** — zero build step, instant load, works offline
- **Signed HttpOnly cookies** — no tokens in localStorage
- **Structured JSON logs** — ready for ELK/Datadog/CloudWatch
- **Path-safe I/O** — `safe_path()` on every file operation

## Quick Start

### Option 1: Local (recommended for development)

```bash
git clone https://github.com/bbm8sus4/SadTalker-Studio.git
cd SadTalker-Studio

# Create venv and install deps
python -m venv venv
source venv/bin/activate
pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
pip install fastapi uvicorn itsdangerous edge-tts

# Download model checkpoints
bash scripts/download_models.sh

# Start server
python webui_app.py
# → http://localhost:8000
# → Login: admin / sadtalker
```

### Option 2: Docker

```bash
cp .env.example .env   # edit ST_USER and ST_PASS
docker compose up -d
# → http://localhost:8000
```

### Custom credentials

```bash
ST_USER=boss ST_PASS=mysecret python webui_app.py
```

## Features

| Feature | Description |
|---------|-------------|
| Text-to-Speech | 7 voices (Thai, English, Japanese, Korean, Chinese) with speed/pitch control |
| Audio upload | Use your own .mp3/.wav instead of TTS |
| Image gallery | 30+ example images or upload your own |
| 4 presets | Draft, Standard, High Quality, Marketing |
| Custom presets | Create/save/delete your own presets (persisted to JSON) |
| Advanced settings | Expression scale, pose style, still mode, Yaw/Pitch/Roll, enhancers |
| History | Browse, rename, download, delete generated videos |
| Upload manager | View and manage uploaded images |
| Dark/Light theme | Auto-detects system preference, toggle in sidebar |
| Auth | Session-based login with signed cookies |
| User guide | Built-in Thai documentation |

## API

Full OpenAPI spec: [`openapi.json`](openapi.json)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/login` | Login (form: username, password) |
| GET | `/logout` | Logout |
| GET | `/api/me` | Current user |
| POST | `/api/generate` | Start video generation |
| GET | `/api/status/{id}` | Poll job progress |
| GET | `/api/history` | List videos |
| PATCH | `/api/history/{file}` | Rename video |
| DELETE | `/api/history/{file}` | Delete video |
| GET | `/api/uploads` | List uploads |
| DELETE | `/api/uploads/{file}` | Delete upload |
| GET/POST/DELETE | `/api/custom-presets` | CRUD presets |
| GET | `/api/voices` | Voice list |
| GET | `/api/presets` | All presets |
| GET | `/api/examples` | Example images |

## Testing

```bash
# Install test deps
pip install pytest pytest-asyncio playwright
python -m playwright install chromium

# Run all tests (server must be running for E2E)
python webui_app.py &
pytest tests/ -v

# Run by suite
pytest tests/test_unit.py -v          # 29 tests — business logic
pytest tests/test_integration.py -v   # 29 tests — API flow + error simulation
pytest tests/test_e2e.py -v           # 18 tests — Playwright mobile viewport
```

**76 tests total** covering path safety, auth, upload validation, CRUD, simulated 500 errors, mobile UI flow.

## CLI Usage

```bash
# Thai female voice (default)
./ss "สวัสดีค่ะ" face.jpg output.mp4

# Thai male voice
VOICE=th-TH-NiwatNeural ./ss "สวัสดีครับ" face.jpg

# English
VOICE=en-US-JennyNeural ./ss "Hello!" face.jpg
```

## Deployment

### Docker Compose (production)

```bash
docker compose up -d
```

Resource limits enforced:
- **Memory:** 8GB max (SadTalker peaks ~4-6GB during inference)
- **CPU:** 4 cores max
- **Logs:** 10MB max per file, 3 rotated files (30MB total)

### CI/CD (GitHub Actions)

Pipeline: `.github/workflows/ci.yml`

```
Push to main
  → Unit tests (29)
  → Integration tests (29)
  → E2E tests (18)        ← blocked if unit/integration fail
  → Docker build + push   ← blocked if ANY test fails
```

Images pushed to `ghcr.io/<user>/sadtalker-studio:latest`

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ST_USER` | `admin` | Login username |
| `ST_PASS` | `sadtalker` | Login password |
| `ST_SECRET` | random | Session signing key (set for multi-worker) |
| `PORT` | `8000` | Server port |

## Security

- Path traversal protection (`safe_path()` on all file I/O)
- XSS prevention (HTML escaping on all user content in DOM)
- Upload validation (file type whitelist + 20MB size limit)
- Rate limiting (30 req/min on `/api/generate`)
- HttpOnly signed session cookies
- No secrets in code (env vars only)

## License

[Apache 2.0](LICENSE) (inherited from SadTalker)
