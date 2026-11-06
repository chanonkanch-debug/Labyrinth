FROM python:3.13-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    LABYRINTH_DB=/data/labyrinth.db LABYRINTH_HOST=0.0.0.0 LABYRINTH_PORT=8080 LABYRINTH_ADMIN_PORT=8090
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY labyrinth ./labyrinth
RUN mkdir -p /data && useradd -r -u 10001 labyrinth && chown labyrinth /data
USER labyrinth
VOLUME /data
EXPOSE 8080 8090
HEALTHCHECK --interval=10s --timeout=3s CMD python -c "import socket; socket.create_connection(('127.0.0.1', 8080), 2)"
CMD ["python", "-m", "labyrinth.serve"]
