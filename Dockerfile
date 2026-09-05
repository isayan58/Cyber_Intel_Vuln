FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src:/app/apps

WORKDIR /app

# Dependencies resolve from pyproject alone, so this layer is cached until the
# dependency list itself changes rather than on every source edit.
COPY pyproject.toml README.md ./
COPY src/vulnintel/__init__.py src/vulnintel/__init__.py
RUN pip install --upgrade pip && pip install -e ".[postgres]"

COPY src/ src/
COPY apps/ apps/
COPY prompts/ prompts/
COPY knowledge_base/ knowledge_base/
COPY evals/ evals/

# Non-root: the container only ever reads public feeds and writes its own volumes.
RUN useradd --create-home --uid 10001 vulnintel \
    && mkdir -p /data/bronze && chown -R vulnintel:vulnintel /data /app
USER vulnintel

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=4)"

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
