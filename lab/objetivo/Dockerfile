# El servidor victima. Debian slim: trae /bin/sh, ping y bash, que es justo lo que
# el escenario de shell inversa necesita para ser realista.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY servidor.py .

EXPOSE 8080
CMD ["python", "servidor.py"]
