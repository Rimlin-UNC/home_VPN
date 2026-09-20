# ============================================================
# StealthNode — бэкенд веб-панели (FastAPI + WebSocket).
# ============================================================
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
# curl нужен для определения внешнего IP при генерации клиентских конфигов
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Примечание по безопасности: контейнер работает от root, т.к. монтируется
# docker.sock (управление ботом, перезапуск сервисов, awg-команды).
# Сокет доступен только внутри сервера; панель защищена JWT (см. SECURITY.md).
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=25s \
    CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=5).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
