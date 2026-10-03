# IRRd 4.5.3 for the oracle (resolve/internal/irrdoracle). gcc and libc6-dev:
# two of its dependencies have no arm64 wheels. graphql-core < 3.3: newer ones
# crash IRRd's HTTP workers at import (whois is unaffected, but the log fills).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends gnupg libpq5 netcat-openbsd procps gcc libc6-dev && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir irrd==4.5.3 'graphql-core<3.3'
RUN useradd --system --create-home irrd && mkdir -p /etc/irrd /var/run/irrd /var/lib/irrd/gnupg /data \
 && chown -R irrd:irrd /var/run/irrd /var/lib/irrd && chmod 700 /var/lib/irrd/gnupg
