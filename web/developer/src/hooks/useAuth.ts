import axios from 'axios';

export function useAuth() {
  const apiUrl = import.meta.env.VITE_API_URL ?? '';
  const idUrl = import.meta.env.VITE_ID_URL ?? 'http://id.wardseal.local';

  const logout = async () => {
    // Redirect to central ID logout page which will clear cookies and local state
    window.location.href = `${idUrl}/logout`;
  };

  return { logout };
}
