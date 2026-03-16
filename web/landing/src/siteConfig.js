const hostname = window.location.hostname

function detectEnvironment() {
  const explicit = import.meta.env.VITE_ENVIRONMENT
  if (explicit) return explicit

  if (hostname.endsWith('.local')) return 'local'
  if (hostname.includes('-staging.') || hostname.startsWith('staging.')) return 'staging'
  return 'production'
}

const environment = detectEnvironment()

const defaults = {
  local: {
    siteBaseUrl: 'http://wardseal.local',
    consoleBaseUrl: 'http://console.wardseal.local',
    helpBaseUrl: 'http://help.wardseal.local',
  },
  staging: {
    siteBaseUrl: 'https://staging.wardseal.com',
    consoleBaseUrl: 'https://console-staging.wardseal.com',
    helpBaseUrl: 'https://help-staging.wardseal.com',
  },
  production: {
    siteBaseUrl: 'https://wardseal.com',
    consoleBaseUrl: 'https://console.wardseal.com',
    helpBaseUrl: 'https://help.wardseal.com',
  },
}

const envDefaults = defaults[environment] || defaults.production

export const siteConfig = {
  environment,
  siteBaseUrl: import.meta.env.VITE_SITE_BASE_URL || envDefaults.siteBaseUrl,
  consoleBaseUrl: import.meta.env.VITE_CONSOLE_BASE_URL || envDefaults.consoleBaseUrl,
  helpBaseUrl: import.meta.env.VITE_HELP_BASE_URL || envDefaults.helpBaseUrl,
  supportEmail: import.meta.env.VITE_SUPPORT_EMAIL || 'support@wardseal.com',
}

export default siteConfig
