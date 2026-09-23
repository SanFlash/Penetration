"""Central safety and assessment configuration.

Targets are allowlisted explicitly. Only add systems you own or are authorized
in writing to assess. The AM Webtech entry below is enabled because the
repository owner requested an assessment of their own website.
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

# Safe browser compatibility profile.
COMPATIBILITY_MAX_PAGES = 12
COMPATIBILITY_VIEWPORTS = [
    (375, 812),
    (390, 844),
    (768, 1024),
    (1366, 768),
    (1440, 900),
    (1920, 1080),
]
