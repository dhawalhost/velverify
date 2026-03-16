FROM node:20-alpine AS builder
WORKDIR /app
ARG VITE_ENVIRONMENT=production
ARG VITE_SITE_BASE_URL=https://wardseal.com
ARG VITE_CONSOLE_BASE_URL=https://console.wardseal.com
ARG VITE_HELP_BASE_URL=https://help.wardseal.com
ARG VITE_SUPPORT_EMAIL=support@wardseal.com
ENV VITE_ENVIRONMENT=$VITE_ENVIRONMENT
ENV VITE_SITE_BASE_URL=$VITE_SITE_BASE_URL
ENV VITE_CONSOLE_BASE_URL=$VITE_CONSOLE_BASE_URL
ENV VITE_HELP_BASE_URL=$VITE_HELP_BASE_URL
ENV VITE_SUPPORT_EMAIL=$VITE_SUPPORT_EMAIL
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
