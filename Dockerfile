# ── Stage 1: Base image ───────────────────────────────────────────────
# We start from an official Python 3.11 image (slim = smaller size)
FROM python:3.11-slim

# ── Who maintains this image (optional, good practice) ────────────────
LABEL maintainer="Dhravya Shetty <dhravyashetty285@gmail.com>"

# ── Set working directory inside the container ────────────────────────
# All commands below will run from /app
WORKDIR /app

# ── Copy only requirements first (Docker caching trick) ───────────────
# If requirements.txt hasn't changed, Docker skips reinstalling packages
# This makes rebuilds much faster
COPY requirements.txt .

# ── Install Python dependencies ───────────────────────────────────────
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy the rest of the project into the container ───────────────────
COPY . .

# ── Tell Docker this container listens on port 5000 ───────────────────
# (This is just documentation — docker-compose.yml actually maps the port)
EXPOSE 5000

# ── Command to run when the container starts ──────────────────────────
CMD ["python", "app.py"]