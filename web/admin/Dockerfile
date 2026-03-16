# Build stage
FROM node:20-alpine AS builder
WORKDIR /app

ARG VITE_AUTHSVC_URL=http://localhost:8080
ARG VITE_DIRSVC_URL=http://localhost:8081
ARG VITE_GOVSVC_URL=http://localhost:8082
ARG VITE_APP_MODE=selfhost

ENV VITE_AUTHSVC_URL=$VITE_AUTHSVC_URL
ENV VITE_DIRSVC_URL=$VITE_DIRSVC_URL
ENV VITE_GOVSVC_URL=$VITE_GOVSVC_URL
ENV VITE_APP_MODE=$VITE_APP_MODE

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Runtime stage
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
