FROM node:20-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev --no-audit --no-fund; \
    else \
      npm install --omit=dev --no-audit --no-fund; \
    fi

COPY . .

RUN mkdir -p uploads data /tmp/uploads /tmp/data && \
    chown -R node:node /app/uploads /app/data /tmp/uploads /tmp/data
USER node

EXPOSE 8080
CMD ["npm", "run", "start:prod"]
