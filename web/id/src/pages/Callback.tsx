import React, { useEffect } from 'react';

/**
 * Callback — Post-login redirect handler for web/id.
 *
 * After a successful login, authsvc sets the httpOnly cookie and the Login
 * page navigates to /callback?redirect_uri=<original-destination>.
 *
 * This page reads redirect_uri and sends the user there.
 * If no redirect_uri is present, falls back to the user profile page.
 */
const Callback: React.FC = () => {
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const redirectUri = params.get('redirect_uri');

    if (redirectUri) {
      // Basic safety check: only allow same-domain redirects
      try {
        const target = new URL(redirectUri);
        const idHost = window.location.hostname; // e.g. id.wardseal.local
        const baseDomain = idHost.replace(/^id\./, ''); // e.g. wardseal.local
        if (target.hostname.endsWith(baseDomain)) {
          window.location.href = redirectUri;
          return;
        }
      } catch {
        // Invalid URL — fall through to default
      }
    }

    // Default: go to profile
    window.location.href = '/profile';
  }, []);

  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="text-center space-y-4">
        <div className="w-10 h-10 border-4 border-primary/30 border-t-primary rounded-full animate-spin mx-auto" />
        <p className="text-muted-foreground text-sm">Redirecting...</p>
      </div>
    </div>
  );
};

export default Callback;
