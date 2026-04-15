FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r /app/requirements.txt

COPY src /app/src

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
	CMD python -c "import os, socket, sys; enabled=os.getenv('WEB_ENABLED','false').strip().lower() in {'1','true','yes','on'}; sys.exit(0) if not enabled else (lambda s: (s.settimeout(2), s.connect(('127.0.0.1', int(os.getenv('WEB_PORT','8080')))), s.close(), 0)[-1])(socket.socket())"

CMD ["python", "-m", "src.main"]
