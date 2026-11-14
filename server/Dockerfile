FROM node:22-alpine
WORKDIR /app
COPY server.js .
ENV DATA_DIR=/data PORT=8080 NODE_ENV=production
VOLUME /data
EXPOSE 8080
USER node
CMD ["node", "server.js"]
