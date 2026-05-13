/**
 * Shared environment configuration for all WardSeal MFEs.
 * Each MFE sets VITE_* variables in its own .env.local file.
 */

export const AppConfig = {
  /** Base URL of the Identity / Login UI (id.wardseal.*) */
  idUrl: (import.meta as any).env?.VITE_ID_URL ?? 'http://id.wardseal.local',

  /** Base URL for API calls — points to the MFE's own nginx proxy */
  apiUrl: (import.meta as any).env?.VITE_API_URL ?? '',

  /** The raw authsvc URL (used only by id MFE for login/token calls) */
  authUrl: (import.meta as any).env?.VITE_AUTH_URL ?? 'http://auth.wardseal.local',

  /** Deployment mode: 'saas' | 'selfhost' */
  mode: (import.meta as any).env?.VITE_APP_MODE ?? 'selfhost',

  isSaaS() { return this.mode === 'saas'; },
  isSelfHost() { return this.mode !== 'saas'; },
};

export default AppConfig;
