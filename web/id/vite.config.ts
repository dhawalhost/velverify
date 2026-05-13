import * as path from "path"
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Auth Service
      '/login': 'http://localhost:8080',
      '/api/v1/signup': 'http://localhost:8080',
      '/logout': 'http://localhost:8080',
      '/oauth2': 'http://localhost:8080',
      '/.well-known': 'http://localhost:8080',
      '/api/v1/mfa': 'http://localhost:8080',      // TOTP, WebAuthn MFA endpoints
      '/api/v1/devices': 'http://localhost:8080',  // Device endpoints
      '/api/v1/apps': 'http://localhost:8080',     // Developer apps
      '/api/v1/api-keys': 'http://localhost:8080', // API keys
      '/api/v1/branding': 'http://localhost:8080', // Branding

      // Directory Service (SCIM & Users/Groups)
      '/scim': 'http://localhost:8081',
      // Regex for directory resources under tenants
      '^/api/v1/tenants/[^/]+/users': 'http://localhost:8081',
      '^/api/v1/tenants/[^/]+/groups': 'http://localhost:8081',

      // Governance Service (Default for /api)
      '/api': 'http://localhost:8082'
    }
  }
})
