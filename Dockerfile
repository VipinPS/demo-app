# ─────────────────────────────────────────────────────────────────
# PQC Demo Application — Dockerfile
#
# Base: Red Hat UBI 9 minimal (contains dynamically-linked OpenSSL)
# The cryptography package links against the system libcrypto/libssl,
# making crypto operations visible to eBPF probes on those libraries.
# ─────────────────────────────────────────────────────────────────

FROM registry.redhat.io/ubi9/python-311:latest

# ---------- system packages -------------------------------------------
# openssl-libs provides libcrypto.so / libssl.so for eBPF observation.
USER root
RUN microdnf install -y openssl openssl-libs && microdnf clean all

# ---------- non-root user ---------------------------------------------
RUN useradd -m -u 1001 appuser
WORKDIR /app

# ---------- Python dependencies ----------------------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---------- Application source -----------------------------------------
COPY app/       ./app/
COPY scripts/   ./scripts/

# ---------- Self-signed TLS certificate (for the local HTTPS demo) -----
# The cert is generated at build time for the internal demo endpoint only.
RUN mkdir -p certs && \
    openssl req -x509 -newkey rsa:2048 \
      -keyout certs/demo.key \
      -out    certs/demo.crt \
      -days   365 \
      -nodes  \
      -subj   "/CN=localhost" && \
    chmod 644 certs/demo.crt certs/demo.key

# ---------- Permissions & runtime user ---------------------------------
RUN chown -R appuser:appuser /app
USER 1001

# ---------- Runtime environment ----------------------------------------
ENV PORT=8080 \
    DEMO_CERT_FILE=/app/certs/demo.crt \
    DEMO_KEY_FILE=/app/certs/demo.key \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

# gunicorn binds to localhost inside the container; the Docker port mapping
# (-p 8080:8080) routes external traffic in.
# We bind to 0.0.0.0 only inside the isolated container network — this is
# intentional for a demo workload container (not a public-facing service).
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "1", \
     "--threads", "4", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app.main:app"]
