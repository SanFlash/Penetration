FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PORT=10000

COPY docker-entrypoint.sh /usr/local/bin/sentinel-entrypoint
RUN chmod +x /usr/local/bin/sentinel-entrypoint

EXPOSE 10000
ENTRYPOINT ["/usr/local/bin/sentinel-entrypoint"]
