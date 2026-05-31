FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Build identifier surfaced in the UI footer. Pass at build time, e.g.
#   docker build --build-arg BUILD_VERSION=$(git describe --tags --always) .
# docker-compose forwards it from the BUILD_VERSION env var (see compose file).
ARG BUILD_VERSION=dev
ENV AGENT_BUILD_VERSION=$BUILD_VERSION

ENV AGENT_DB_PATH=/data/tasks.db \
    PYTHONUNBUFFERED=1
RUN mkdir -p /data

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
