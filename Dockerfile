# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.11-slim

# ── System-level tools ────────────────────────────────────────────────────────
# FIX 1: was `& \` (background operator) — must be `&&` so rm -rf only runs
#         after apt-get succeeds, not simultaneously with it.
# --no-install-recommends keeps the image lean.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl \
        git \
 && rm -rf /var/lib/apt/lists/*

# ── Layer-cache optimisation ──────────────────────────────────────────────────
# FIX 3: Copy requirements.txt BEFORE copying the full project.
#         Docker caches this layer; pip install only re-runs when
#         requirements.txt changes, not on every code edit.
WORKDIR /app
COPY requirements.txt /app/requirements.txt

# FIX 2: was `langchain-openai` — this project uses langchain-anthropic.
# FIX 3 cont.: install the full requirements.txt, not a hard-coded subset.
RUN pip install --no-cache-dir -r requirements.txt

# ── Application code ──────────────────────────────────────────────────────────
# FIX 4: .dockerignore (see that file) prevents .env from being copied here.
COPY . /app

# ── Non-root user (security hardening) ───────────────────────────────────────
RUN useradd -m appuser \
 && chown -R appuser /app
USER appuser

# ── Streamlit port ────────────────────────────────────────────────────────────
EXPOSE 8501

# ── Health check ──────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# ── Entrypoint ────────────────────────────────────────────────────────────────
# FIX 5: --server.headless=true stops Streamlit from trying to open a browser
#         inside the container (which hangs the process).
#         --server.address=0.0.0.0 makes it reachable from outside the container.
CMD ["streamlit", "run", "app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false"]
