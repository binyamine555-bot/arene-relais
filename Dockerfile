FROM python:3.12-slim
WORKDIR /app
ADD https://github.com/ekzhang/bore/releases/download/v0.6.0/bore-v0.6.0-x86_64-unknown-linux-musl.tar.gz /tmp/bore.tgz
RUN tar xzf /tmp/bore.tgz -C /usr/local/bin && rm /tmp/bore.tgz && chmod +x /usr/local/bin/bore
COPY smash_relay.py start.sh garde_eveil.py ./
RUN chmod +x start.sh
ENV PYTHONUNBUFFERED=1
CMD ["./start.sh"]
