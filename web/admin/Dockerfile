# Build stage
FROM node:22.14-alpine3.21 AS builder

WORKDIR /app

# Build arguments for VITE environment variables
ARG VITE_AUTHSVC_URL
ARG VITE_DIRSVC_URL
ARG VITE_GOVSVC_URL
ARG VITE_APP_MODE=selfhost

# Set environment variables for the build process
ENV VITE_AUTHSVC_URL=$VITE_AUTHSVC_URL
ENV VITE_DIRSVC_URL=$VITE_DIRSVC_URL
ENV VITE_GOVSVC_URL=$VITE_GOVSVC_URL
ENV VITE_APP_MODE=$VITE_APP_MODE

# Install dependencies first for better caching
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY . .
RUN npm run build

# Runtime stage
# Using Nginx stable Alpine
FROM nginx:1.27.4-alpine3.21

# Standardized labels
LABEL org.opencontainers.image.source="https://github.com/dhawalhost/wardseal"
LABEL org.opencontainers.image.description="WardSeal Admin Management Console"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy build artifacts to Nginx html directory
COPY --from=builder /app/dist /usr/share/nginx/html

# Health check for Nginx
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1:80/ || exit 1

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
