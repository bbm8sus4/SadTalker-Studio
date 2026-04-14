# ═══════════════════════════════════════════════════════════════
# SadTalker Studio — Multi-stage Production Dockerfile
#
# Stage 1: deps    — install Python packages into a venv
# Stage 2: runtime — slim image with only runtime files
#
# Build:  docker build -t sadtalker-studio .
# Run:    docker run -p 8000:8000 -e ST_USER=admin -e ST_PASS=secret sadtalker-studio
# ═══════════════════════════════════════════════════════════════

# ── Stage 1: Dependencies ────────────────────────────────────
FROM python:3.11-slim AS deps

WORKDIR /build

# System deps for OpenCV, scipy, audio processing
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc g++ \
    libgl1 libglib2.0-0 libsm6 libxext6 libxrender1 \
    ffmpeg libsndfile1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt req.txt ./
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    torch torchvision --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir \
    fastapi==0.135.3 uvicorn==0.44.0 itsdangerous==2.2.0 edge-tts==7.2.8


# ── Stage 2: Runtime ─────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Runtime system deps only (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 libglib2.0-0 libsm6 libxext6 libxrender1 \
    ffmpeg libsndfile1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r app && useradd -r -g app -d /app app

# Copy venv from deps stage
COPY --from=deps /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Copy application code (only what's needed)
COPY webui_app.py inference.py ./
COPY static/ ./static/
COPY src/ ./src/
COPY examples/ ./examples/
COPY checkpoints/ ./checkpoints/
COPY ss generate.sh ./

# Create writable dirs
RUN mkdir -p uploads outputs && chown -R app:app /app

# Non-root user
USER app

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/login')" || exit 1

EXPOSE 8000

# Production server: 2 workers, access log off (we have our own logging)
CMD ["uvicorn", "webui_app:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "2", \
     "--access-log", \
     "--log-level", "warning"]
