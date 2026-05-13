import React, { useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';
import axios from 'axios';

interface AuthGuardProps {
  children: React.ReactElement;
}

/**
 * AuthGuard — Verifies the httpOnly session cookie is valid.
 *
 * Makes a lightweight API call to /api/v1/user/profile:
 *   - 200 OK  → render children
 *   - 401     → redirect to id.wardseal.* login?redirect_uri=<current-url>
 *
 * VITE_API_URL  points to this MFE's nginx proxy (e.g. http://admin.wardseal.local)
 * VITE_ID_URL   points to the identity portal (e.g. http://id.wardseal.local)
 */
const AuthGuard: React.FC<AuthGuardProps> = ({ children }) => {
  const [status, setStatus] = useState<'loading' | 'ok' | 'redirect'>('loading');

  const apiUrl = import.meta.env.VITE_API_URL ?? '';
  const idUrl = import.meta.env.VITE_ID_URL ?? 'http://id.wardseal.local';

  useEffect(() => {
    axios
      .get(`${apiUrl}/api/v1/user/profile`, { withCredentials: true })
      .then(() => setStatus('ok'))
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
