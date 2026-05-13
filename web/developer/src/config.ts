// config.ts
// Manages feature flags and configuration based on build environment.

const APP_MODE = import.meta.env.VITE_APP_MODE || 'selfhost'; // Default to 'selfhost' (Enterprise)

export const Config = {
    mode: APP_MODE,
    isSaaS: APP_MODE === 'saas',
    isSelfHost: APP_MODE !== 'saas', // 'selfhost' or default
    features: {
        landingPage: APP_MODE === 'saas',
        publicSignup: APP_MODE === 'saas',
        pricing: APP_MODE === 'saas',
        // In self-host, we might still allow "setup" wizard for initial owner, but not public open signup.
        setupWizard: true,
    }
};

export default Config;
