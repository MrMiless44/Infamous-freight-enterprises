FROM node:20-alpine
WORKDIR /app

COPY package.json ./
RUN npm install -g pnpm && pnpm install --prod=false

COPY . .
RUN pnpm prisma:generate && pnpm build
RUN pnpm prune --prod

EXPOSE 4000
CMD ["node", "dist/server.js"]
