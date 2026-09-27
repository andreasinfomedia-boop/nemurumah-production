FROM node:20-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
RUN mkdir -p /app/data /app/public/uploads && chown -R node:node /app
USER node
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node","server.js"]
