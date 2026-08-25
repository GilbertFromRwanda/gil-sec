# syntax=docker/dockerfile:1
FROM node:20-alpine

WORKDIR /app

# Match the pnpm version pinned in package.json
RUN corepack enable && corepack prepare pnpm@10.33.2 --activate

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .

# Dashboard HTTP + its WebSocket feed. Override at runtime (e.g.
# `docker run -e DASHBOARD_PORT=9000 -e WS_PORT=9001 -p 9000:9000 -p 9001:9001 ...`)
# if you don't want the defaults used here.
ENV DASHBOARD_PORT=5005
ENV WS_PORT=8081
EXPOSE 5005 8081

CMD ["pnpm", "run", "monitor"]
