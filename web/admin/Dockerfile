# Build stage
FROM node:20-alpine AS builder
WORKDIR /app

ARG VITE_GOVSVC_URL=http://localhost:8082
ENV VITE_GOVSVC_URL=$VITE_GOVSVC_URL

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Runtime stage
FROM nginx:1.27-alpine
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
