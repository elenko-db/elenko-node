# Debian slim (glibc): sharp provides @img/sharp-linux-arm / sharp-linux-arm64 prebuilds.
# node:alpine on Raspberry Pi armv7 resolves to linuxmusl-arm, which sharp does not ship — startup fails.
FROM node:20-bookworm-slim

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .
EXPOSE 3000

CMD ["node", "server.js"]
