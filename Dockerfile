FROM node:20-alpine

WORKDIR /app

# Copy files
COPY . .

# Install dependencies
RUN npm install --omit=dev --ignore-scripts

RUN chmod +x start-all.sh || true

EXPOSE 5050

CMD ["node", "server.js"]
