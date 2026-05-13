# Build stage
FROM node:22.14-alpine3.21 AS builder

WORKDIR /app

# Build arguments for VITE environment variables
ARG VITE_API_URL
ARG VITE_AUTHSVC_URL
ARG VITE_DIRSVC_URL
ARG VITE_GOVSVC_URL
ARG VITE_ID_URL
ARG VITE_AUTH_URL
ARG VITE_APP_MODE=selfhost

# Set environment variables for the build process
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_AUTHSVC_URL=$VITE_AUTHSVC_URL
ENV VITE_DIRSVC_URL=$VITE_DIRSVC_URL
ENV VITE_GOVSVC_URL=$VITE_GOVSVC_URL
ENV VITE_ID_URL=$VITE_ID_URL
ENV VITE_AUTH_URL=$VITE_AUTH_URL
ENV VITE_APP_MODE=$VITE_APP_MODE

# Install dependencies first for better caching
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY . .
RUN npm run build

# Runtime stage
FROM nginx:1.27.4-alpine3.21

LABEL org.opencontainers.image.source="https://github.com/dhawalhost/wardseal"
LABEL org.opencontainers.image.description="WardSeal User App Portal"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1:80/ || exit 1

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
