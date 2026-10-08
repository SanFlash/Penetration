"""Central safety and assessment configuration.

Only add systems you own or have explicit written authorization to assess.
"""

ALLOWED_HOSTS = [
    "127.0.0.1:5000",
    "localhost:5000",
    "127.0.0.1:3000",
    "localhost:3000",
    "amwebtech.com",
    "www.amwebtech.com",
]

DEFAULT_TARGET = "http://127.0.0.1:5000"

RATE_LIMIT_RPS = 2
# Persistent runtime storage. Render mounts the persistent disk at /var/data.
# Locally this falls back to the repository's evidence/reports directories.
import os

_DATA_DIR = os.getenv("SENTINEL_DATA_DIR", "").strip()
if _DATA_DIR:
    EVIDENCE_DIR = os.path.join(_DATA_DIR, "evidence")
    REPORT_DIR = os.path.join(_DATA_DIR, "reports")
else:
    EVIDENCE_DIR = "evidence"
    REPORT_DIR = "reports"

DEMO_USERNAME = "bob"
DEMO_PASSWORD = "bob_pw"

# Runtime controls.
COMPATIBILITY_MAX_PAGES = int(os.getenv("SENTINEL_COMPATIBILITY_MAX_PAGES", "50"))
ACTIVE_SECURITY_MAX_URLS = int(os.getenv("SENTINEL_ACTIVE_SECURITY_MAX_URLS", "50"))
PENTEST_TARGET_ORIGIN = "https://amwebtech.com"

# Dedicated security-only engine. These are deliberately bounded so the
# assessment can be aggressive in coverage without becoming destructive.
SECURITY_MAX_URLS = int(os.getenv("SENTINEL_SECURITY_MAX_URLS", "120"))
SECURITY_MAX_PROBES = int(os.getenv("SENTINEL_SECURITY_MAX_PROBES", "1200"))
SECURITY_TIMEOUT = 10
SECURITY_RATE_RPS = 2
SECURITY_PROGRESS_INTERVAL = 10

# Input-stress fuzzing. Same-origin GET requests only; no form submission.
STRESS_MAX_URLS = int(os.getenv("SENTINEL_STRESS_MAX_URLS", "100"))
STRESS_MAX_PROBES = int(os.getenv("SENTINEL_STRESS_MAX_PROBES", "700"))
STRESS_RATE_RPS = 4
STRESS_TIMEOUT = 10

# Valid/invalid input validation. Same-origin GET requests only.
VALIDATION_MAX_URLS = int(os.getenv("SENTINEL_VALIDATION_MAX_URLS", "80"))
VALIDATION_MAX_PROBES = int(os.getenv("SENTINEL_VALIDATION_MAX_PROBES", "600"))
VALIDATION_RATE_RPS = 3
VALIDATION_TIMEOUT = 10

# Passive route/API discovery. Network activity remains GET-only; discovered
# state-changing methods are inventory candidates and are never submitted.
ROUTE_DISCOVERY_MAX_PAGES = int(os.getenv("SENTINEL_ROUTE_DISCOVERY_MAX_PAGES", "100"))
ROUTE_DISCOVERY_MAX_ASSETS = int(os.getenv("SENTINEL_ROUTE_DISCOVERY_MAX_ASSETS", "80"))
ROUTE_DISCOVERY_MAX_CANDIDATES = int(os.getenv("SENTINEL_ROUTE_DISCOVERY_MAX_CANDIDATES", "1200"))
ROUTE_DISCOVERY_TIMEOUT = 8
ROUTE_DISCOVERY_MAX_RUNTIME = int(os.getenv("SENTINEL_ROUTE_DISCOVERY_MAX_RUNTIME", "300"))

# Live report rendering can be expensive on large finding sets. Keep the report
# genuinely live, but avoid rebuilding the complete HTML document after every
# short phase.
LIVE_REPORT_MIN_INTERVAL = float(os.getenv("SENTINEL_LIVE_REPORT_MIN_INTERVAL", "12"))


# Unified deep-pentest coverage controls. These defaults favor breadth while
# remaining bounded and read-only; environment variables allow larger staging
# assessments without changing source code.
PENTEST_MAX_DISCOVERED_URLS = int(os.getenv("SENTINEL_PENTEST_MAX_DISCOVERED_URLS", "300"))
AGGRESSIVE_MAX_URLS = int(os.getenv("SENTINEL_AGGRESSIVE_MAX_URLS", "100"))
AGGRESSIVE_MAX_PROBES = int(os.getenv("SENTINEL_AGGRESSIVE_MAX_PROBES", "700"))
COMPREHENSIVE_MAX_URLS = int(os.getenv("SENTINEL_COMPREHENSIVE_MAX_URLS", "120"))
COMPREHENSIVE_MAX_PROBES = int(os.getenv("SENTINEL_COMPREHENSIVE_MAX_PROBES", "800"))

# Controlled state-change testing. Every action must target a configured disposable
# resource and include an explicit rollback operation. Keep the default run small.
INTRUSIVE_MAX_ACTIONS = 3
INTRUSIVE_TIMEOUT = 10

# The professional pentest profile intentionally uses Chromium only.
# Six responsive sizes provide mobile/tablet/desktop coverage without
# multiplying runtime across Firefox/WebKit.
COMPATIBILITY_VIEWPORTS = [
    (375, 812),
    (390, 844),
    (768, 1024),
    (1366, 768),
    (1440, 900),
    (1920, 1080),
]
