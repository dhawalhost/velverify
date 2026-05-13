/**
 * useAuth — Shared authentication hook for all WardSeal MFEs.
 *
 * Since wardseal_access_token is httpOnly, JavaScript cannot read it directly.
 * We verify the session by calling the /api/v1/user/profile endpoint.
 * - 200 OK  → session is valid
 * - 401     → redirect to id.wardseal.* login with ?redirect_uri=<current-url>
 *
 * The ID_URL and API_URL are injected as Vite environment variables per-MFE.
 */
import { useEffect, useState } from 'react';
import axios from 'axios';

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  roles: string[];
  tenantId: string;
}

interface UseAuthResult {
  user: AuthUser | null;
  loading: boolean;
  logout: () => Promise<void>;
}

export function useRequireAuth(): UseAuthResult {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const idUrl = (import.meta as any).env?.VITE_ID_URL ?? '';
  const apiUrl = (import.meta as any).env?.VITE_API_URL ?? '';

  useEffect(() => {
    const verify = async () => {
      try {
        const res = await axios.get(`${apiUrl}/api/v1/user/profile`, {
          withCredentials: true, // Send the httpOnly cookie
        });
        setUser(res.data);
      } catch {
        // Not authenticated — redirect to id portal
        const redirectUri = encodeURIComponent(window.location.href);
        window.location.href = `${idUrl}/login?redirect_uri=${redirectUri}`;
      } finally {
        setLoading(false);
      }
    };
    verify();
  }, [apiUrl, idUrl]);

  const logout = async () => {
    try {
      await axios.get(`${apiUrl}/t/${user?.tenantId}/logout`, {
        withCredentials: true,
      });
    } catch {
      // Ignore logout errors — clear local state regardless
    }
    window.location.href = `${idUrl}/login`;
  };

  return { user, loading, logout };
}

/**
 * useAuth — Lightweight hook for components that just need the logout action.
 * Does NOT redirect on missing session (use useRequireAuth for protected pages).
 */
export function useAuth() {
  const apiUrl = (import.meta as any).env?.VITE_API_URL ?? '';
  const idUrl = (import.meta as any).env?.VITE_ID_URL ?? '';

  const logout = async () => {
    try {
      await axios.get(`${apiUrl}/logout`, { withCredentials: true });
    } catch {
      // ignore
    }
    window.location.href = `${idUrl}/login`;
  };

  return { logout };
}
