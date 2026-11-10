# ── Stage 1: builder ───────────────────────────────────────────────────
# Compiles any dependency that has no musllinux wheel. Alpine uses musl
# rather than glibc, so a few packages (historically lxml, and anything
# pulling cryptography) may need a real toolchain.
#
# The whole point of this stage is that the toolchain NEVER reaches the
# final image: we build a virtualenv in /opt/venv and copy only that
# directory into the runtime stage. That keeps the shipped image small
# and removes compilers from the attack surface.
FROM python:3.12-alpine AS builder

# Build-time-only packages. -dev headers are required to compile against
# libxml2/libxslt, and build-base supplies gcc/musl-dev.
RUN apk add --no-cache \
        build-base \
        libxml2-dev \
        libxslt-dev \
        libffi-dev

# Isolated virtualenv we can copy wholesale into the runtime stage.
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

# Upgrade pip first so wheel resolution is current, then install deps.
# --no-cache-dir keeps the builder layer from ballooning.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r /tmp/requirements.txt


# ── Stage 2: runtime ───────────────────────────────────────────────────
FROM python:3.12-alpine AS runtime

# Runtime shared libraries ONLY — the -dev headers and compilers stay in
# the builder stage. tzdata is NOT optional: APScheduler evaluates cron
# expressions against the container's local time, so without tzdata (and
# a TZ setting) BACKUP_CRON="0 2 * * *" would silently mean 02:00 UTC
# instead of 02:00 local. ca-certificates is needed by requests/boto3 for
# outbound HTTPS to Wazuh, KEV, S3/MinIO and Telegram.
RUN apk add --no-cache \
        libxml2 \
        libxslt \
        libffi \
        tzdata \
        ca-certificates \
 && adduser -D -u 10001 -s /sbin/nologin appuser

# Copy only the virtualenv from the builder — no toolchain, no pip cache.
COPY --from=builder /opt/venv /opt/venv

# Python runtime behaviour:
#   PYTHONDONTWRITEBYTECODE — no .pyc files, keeps read-only rootfs clean
#   PYTHONUNBUFFERED        — logs appear immediately in `docker logs`
#   TZ                      — cron + timestamps land in the intended zone
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Jakarta

WORKDIR /app

# Copy the application with ownership set at copy time, so the non-root
# user can read everything without a later recursive chown layer.
COPY --chown=appuser:appuser . /app

# Writable locations required by the process. The app itself is stateless
# (no local file writes — imports/exports are in-memory, backups go to
# S3), so /app stays read-only and only /tmp needs to be writable. The
# compose file mounts a tmpfs there and enables read_only: true; creating
# the dir here with correct ownership keeps that working.
RUN install -d -o appuser -g appuser /tmp/app

USER appuser

# Port the app listens on (HTTPS when TLS_CERT_FILE/TLS_KEY_FILE are set).
EXPOSE 5000

# Liveness probe. /auth/login always renders for an anonymous request and
# does not require MongoDB — matching the app's "boot without Mongo"
# contract, so the probe reflects the web tier, not the database.
#
# Implemented in Python, NOT wget: BusyBox wget (alpine's) has no
# --no-check-certificate option, so it cannot talk to our self-signed
# HTTPS endpoint at all.
#
# The probe asserts the INTENDED transport rather than accepting either.
# An earlier revision tried HTTPS and silently fell back to HTTP, which
# meant a container serving plaintext because its certificate was broken
# still reported `healthy` — hiding the exact misconfiguration the
# fail-closed entrypoint exists to prevent. Now:
#   - default (TLS expected): probe HTTPS only; a TLS failure -> unhealthy
#   - ALLOW_INSECURE_HTTP=true: probe HTTP only
# The scheme is chosen from the same variable the entrypoint uses, so the
# health verdict can never disagree with the actual serving mode.
# A response below 500 counts as alive, so redirects to the login page are
# fine and the probe does not break if that route's status code changes.
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD [ "$ALLOW_INSECURE_HTTP" = "true" ] \
        && python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/auth/login',timeout=5).status<500 else 1)" \
        || python -c "import ssl,urllib.request,sys; \
ctx=ssl._create_unverified_context(); \
req=urllib.request.Request('https://127.0.0.1:5000/auth/login'); \
sys.exit(0 if urllib.request.urlopen(req,context=ctx,timeout=5).status<500 else 1)"

# Default command = the WEB role. TLS files are read from env at runtime
# (gunicorn --certfile/--keyfile), which is why the override lives in
# docker-compose.yml rather than here: the scheduler container reuses this
# same image with a completely different command.
#
#   gthread + 1 worker: the app makes long BLOCKING outbound HTTP calls
#   (LLM timeout 180s, KEV 90s). With gunicorn's default sync worker, a
#   handful of slow requests would exhaust every worker and stall the UI.
#   Threads absorb that without adding processes. One worker also means
#   there is no per-worker scheduler duplication to reason about.
#
#   --worker-tmp-dir /tmp/app: gunicorn's heartbeat file needs a writable
#   location; pointing it at the tmpfs keeps the read-only rootfs valid.
#
# NOTE: the CMD below is the no-TLS fallback so the image is runnable on
# its own (`docker run`) for debugging. compose always supplies the TLS
# variant via `command:`.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--worker-class", "gthread", "--workers", "1", "--threads", "8", "--worker-tmp-dir", "/tmp/app", "--access-logfile", "-", "--error-logfile", "-", "app:create_app()"]
