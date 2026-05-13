import axios from 'axios';

export function useAuth() {
  const apiUrl = import.meta.env.VITE_API_URL ?? '';

  const logout = async () => {
    try {
      await axios.get(`${apiUrl}/logout`, { withCredentials: true });
    } catch {
      // ignore
    }
    window.location.href = '/login';
  };

  return { logout };
}
