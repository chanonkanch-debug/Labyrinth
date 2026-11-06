FROM node:22-slim
WORKDIR /app
COPY package.json next.config.js ./
RUN npm install
COPY app ./app
RUN npm run build
ENV PORT=8000 NODE_ENV=production
EXPOSE 8000
CMD ["npm", "start"]
