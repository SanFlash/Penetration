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
EVIDENCE_DIR = "evidence"

DEMO_USERNAME = "bob"
DEMO_PASSWORD = "bob_pw"

# Runtime controls.
COMPATIBILITY_MAX_PAGES = 12
ACTIVE_SECURITY_MAX_URLS = 12
PENTEST_TARGET_ORIGIN = "https://amwebtech.com"

# Dedicated security-only engine. These are deliberately bounded so the
# assessment can be aggressive in coverage without becoming destructive.
SECURITY_MAX_URLS = 60
SECURITY_MAX_PROBES = 500
SECURITY_TIMEOUT = 10
SECURITY_RATE_RPS = 2
SECURITY_PROGRESS_INTERVAL = 10

# Passive route/API discovery. Network activity remains GET-only; discovered
# state-changing methods are inventory candidates and are never submitted.
ROUTE_DISCOVERY_MAX_PAGES = 8
ROUTE_DISCOVERY_MAX_ASSETS = 20
ROUTE_DISCOVERY_MAX_CANDIDATES = 200
ROUTE_DISCOVERY_TIMEOUT = 8
ROUTE_DISCOVERY_MAX_RUNTIME = 120

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
