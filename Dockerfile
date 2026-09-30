FROM node:22-alpine
WORKDIR /app
COPY package.json server.js agent-sim.js test.js ./
COPY public ./public
ENV NODE_ENV=production DATA_DIR=/data PORT=3000
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 3000
HEALTHCHECK CMD wget -qO- http://localhost:3000/v1/health || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
