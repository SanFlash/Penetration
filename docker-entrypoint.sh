#!/bin/bash
set -e

mkdir -p /var/data/evidence /var/data/reports
chown -R pwuser:pwuser /var/data

exec su -s /bin/bash pwuser -c 'gunicorn --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 4 --timeout 180 web:app'
