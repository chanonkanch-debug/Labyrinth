FROM node:22-slim
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY server.js .
ENV PORT=8000
EXPOSE 8000
CMD ["node", "server.js"]
