FROM node:18-alpine

WORKDIR /usr/src/app

# Alpine'a openssl 1.1 ve diğer gerekli paketleri yükle
RUN apk add --no-cache openssl1.1-compat

COPY package*.json ./

RUN npm install

COPY . .

RUN npx prisma generate

RUN npm run build

EXPOSE 3000

CMD ["node", "dist/main.js"]