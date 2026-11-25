FROM node:24-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends curl ca-certificates tar \
  && curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared \
  && chmod +x /usr/local/bin/cloudflared \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json* ./
COPY packages ./packages
COPY apps ./apps
COPY scripts ./scripts

RUN npm install --omit=dev

ENV NODE_ENV=production \
    YOUPI_MODE=production \
    USE_SQLITE_FALLBACK=true \
    PORT=10000

EXPOSE 10000

CMD ["node", "scripts/render-boot.js"]
