/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_GOVSVC_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

export {}
