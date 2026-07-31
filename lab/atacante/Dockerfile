# El atacante: solo necesita curl para disparar el exploit y netcat para escuchar
# la shell inversa que le devuelve la victima.
FROM debian:12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root
COPY exploit.sh .
RUN chmod +x exploit.sh

# Se queda vivo esperando a que ./atacar.sh dispare el exploit dentro.
CMD ["sleep", "infinity"]
