FROM node:24.18.1-alpine3.24 AS build
WORKDIR /src
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/protocol/package.json packages/protocol/package.json
COPY services/relay/package.json services/relay/package.json
COPY apps/desktop/package.json apps/desktop/package.json
RUN npm ci --ignore-scripts --workspace @airvault/protocol --workspace @airvault/relay --include-workspace-root
COPY packages/protocol packages/protocol
COPY services/relay services/relay
RUN npm run build -w @airvault/protocol && npm run build -w @airvault/relay && npm prune --omit=dev

FROM node:24.18.1-alpine3.24
ENV NODE_ENV=production AIRVAULT_RELAY_HOST=0.0.0.0 AIRVAULT_RELAY_PORT=8787 AIRVAULT_MAX_CONNECTIONS=1000
WORKDIR /app
USER node
COPY --from=build --chown=node:node /src/node_modules ./node_modules
COPY --from=build --chown=node:node /src/packages/protocol/dist ./packages/protocol/dist
COPY --from=build --chown=node:node /src/packages/protocol/package.json ./packages/protocol/package.json
COPY --from=build --chown=node:node /src/services/relay/dist ./services/relay/dist
COPY --from=build --chown=node:node /src/services/relay/package.json ./services/relay/package.json
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8787/healthz || exit 1
CMD ["node", "services/relay/dist/index.js"]
