# EDT PoC service image: F01 Claim & Evidence Service + F08 import adapter + F03 graph service.
# One deployable, three database identities (DATABASE_URL, IMPORT_DATABASE_URL, GRAPH_DATABASE_URL).
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv/edt
COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --no-cache-dir . && adduser --disabled-password --gecos "" edt && mkdir -p /srv/edt/.evidence && chown -R edt /srv/edt
COPY migrations ./migrations
COPY fixtures ./fixtures
COPY scripts ./scripts
USER edt
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"
CMD ["python", "-m", "app"]
