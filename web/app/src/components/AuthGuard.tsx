import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface AuthGuardProps {
  children: React.ReactElement;
}

/**
 * AuthGuard — Verifies the httpOnly session cookie is valid and seeds tenant context.
 *
 * On success:
 *   1. Validates session via /api/v1/user/profile (uses cookie)
 *   2. Extracts tenantID + userId from the profile response
 *   3. Seeds localStorage so axios interceptors can forward X-Tenant-ID / X-User-ID
 *      to cross-origin services (govsvc, dirsvc at api.wardseal.local)
 *
 * On failure:
 *   - Redirects to id.wardseal.* login with current URL as redirect_uri
 *
 * VITE_API_URL  points to this MFE's nginx proxy (e.g. http://app.wardseal.local)
 * VITE_ID_URL   points to the identity portal (e.g. http://id.wardseal.local)
 */
const AuthGuard: React.FC<AuthGuardProps> = ({ children }) => {
  const [status, setStatus] = useState<'loading' | 'ok' | 'redirect'>('loading');

  const apiUrl = (import.meta as any).env?.VITE_API_URL ?? '';
  const idUrl = (import.meta as any).env?.VITE_ID_URL ?? 'http://id.wardseal.local';

  useEffect(() => {
    axios
      .get(`${apiUrl}/api/v1/user/profile`, { withCredentials: true })
      .then((res) => {
        // Seed tenant context into localStorage so govsvc/dirsvc interceptors
        // can attach X-Tenant-ID on cross-origin requests to api.wardseal.local.
        const profile = res.data;
        const tenantID = profile?.tenant_id ?? profile?.tenantID ?? profile?.tenant?.id ?? '';
        const userId = profile?.user_id ?? profile?.userID ?? profile?.id ?? '';
        const tenantSlug = profile?.tenant_slug ?? profile?.tenant?.slug ?? '';

        if (tenantID) localStorage.setItem('tenantID', tenantID);
        if (userId) localStorage.setItem('userId', userId);
        if (tenantSlug) localStorage.setItem('tenantSlug', tenantSlug);

        setStatus('ok');
      })
      .catch(() => {
        const redirectUri = encodeURIComponent(window.location.href);
        window.location.href = `${idUrl}/login?redirect_uri=${redirectUri}`;
        setStatus('redirect');
      });
  }, [apiUrl, idUrl]);

  if (status === 'loading') {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="w-10 h-10 border-4 border-primary/30 border-t-primary rounded-full animate-spin" />
      </div>
    );
  }

  if (status === 'redirect') {
    return null; // Navigating away
  }

  return children;
};

export default AuthGuard;
