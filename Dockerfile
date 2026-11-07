FROM node:26-alpine
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000 DATABASE_PATH=/data/verdant.sqlite
WORKDIR /app
COPY --chown=node:node . .
RUN mkdir -p /data && chown -R node:node /data /app
USER node
EXPOSE 3000
CMD ["node", "src/server.mjs"]
