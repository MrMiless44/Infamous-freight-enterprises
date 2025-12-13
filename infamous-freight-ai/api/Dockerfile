FROM node:20-bookworm-slim

WORKDIR /app

RUN apt-get update   && apt-get install -y openssl   && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci

COPY . .

EXPOSE 4000

CMD ["npm","start"]
