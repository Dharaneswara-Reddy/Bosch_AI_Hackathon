FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json ./
COPY vendor ./vendor
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY src ./src
COPY scripts ./scripts
RUN chown -R node:node /app
USER node
CMD ["npm", "start"]
