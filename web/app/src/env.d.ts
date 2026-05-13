/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL?: string
  readonly VITE_AUTHSVC_URL?: string
  readonly VITE_DIRSVC_URL?: string
  readonly VITE_GOVSVC_URL?: string
  readonly VITE_ID_URL?: string
  readonly VITE_AUTH_URL?: string
  readonly VITE_APP_MODE?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

export {}
