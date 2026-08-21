FROM node:20-alpine

WORKDIR /frontend

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 3000

# Run Vite dev server bound to 0.0.0.0 for docker access
CMD ["npm", "run", "dev", "--", "--host"]
