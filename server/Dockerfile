FROM node:22-alpine

RUN apk add --no-cache tzdata

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

COPY src/ ./src/

ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/api/health >/dev/null || exit 1

CMD ["node", "src/index.js"]
