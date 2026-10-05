#!/bin/bash
set -e

# Render mounts the persistent disk at runtime. Do not run Playwright's
# browser installer here: the official Playwright base image already
# contains the browser and its OS dependencies.
mkdir -p /var/data/evidence /var/data/reports

# Fail fast with a useful import error before Gunicorn starts.
python -c "import web; import reports.report_generator; print(\"[SENTINEL] application imports OK\")"

exec gunicorn --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 4 --timeout 180 web:app
