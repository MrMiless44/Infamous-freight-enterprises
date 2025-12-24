FROM node:20-alpine
WORKDIR /app

COPY package.json ./
RUN npm install -g pnpm && pnpm install --prod

COPY . .
RUN pnpm prisma:generate && pnpm build

EXPOSE 4000
CMD ["node", "dist/server.js"]
