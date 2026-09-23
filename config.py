"""
config.py — target configuration and the framework's central safety control.

READ THIS BEFORE ADDING A TARGET.

ALLOWED_HOSTS is an explicit allowlist. Every module in this framework
(recon, scanners, auth) MUST check its target against this list before
sending a single request, and MUST refuse to proceed if the target is not
present. This is not a formality — it is the one thing standing between
"authorized security testing" and "unauthorized access."

Only add a host here if ONE of the following is true:
  1. You personally own it, OR
  2. You have explicit, written authorization to test it, OR
  3. It is a dedicated local training lab (OWASP Juice Shop, DVWA, WebGoat,
     or the demo_target/ app shipped in this repository).

Do NOT add a production third-party domain "just to see." The framework
will refuse to run against it (see utils/scope.py), and modifying the code
to bypass that check would mean testing without authorization, which is
illegal in most jurisdictions regardless of intent.
"""

# Format: "host" or "host:port" exactly as it appears in the target URL.
ALLOWED_HOSTS = [
    "127.0.0.1:5000",   # this repo's own demo_target/app.py
    "localhost:5000",
    "127.0.0.1:3000",   # OWASP Juice Shop, if run via Docker (see README)
    "localhost:3000",
]

# Default target for a bare `python main.py` run with no --target flag.
DEFAULT_TARGET = "http://127.0.0.1:5000"

# Requests-per-second ceiling enforced by utils/http_client.py.
RATE_LIMIT_RPS = 5

# Where evidence (raw requests/responses, screenshots, JSON findings) is written.
EVIDENCE_DIR = "evidence"

# Default demo credentials for auth/session.py against demo_target/app.py.
DEMO_USERNAME = "bob"
DEMO_PASSWORD = "bob_pw"
