FROM node:24-bookworm-slim AS client-build
WORKDIR /build/client
COPY client/package*.json ./
RUN npm ci
COPY client/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SECURITY_INSTANCE=/data BIND=0.0.0.0:5001
WORKDIR /app/server
COPY server/requirements-live.txt ./
RUN pip install --no-cache-dir -r requirements-live.txt
RUN useradd --uid 10001 --create-home appuser && mkdir /data && chown appuser:appuser /data && chmod 700 /data
COPY server/ ./
COPY --from=client-build /build/client/dist /app/client/dist
COPY client/public /app/client/public
USER appuser
EXPOSE 5001
CMD ["gunicorn", "--config", "gunicorn.conf.py", "wsgi:app"]
