/**
 * Custom hook for authentication operations.
 * Provides logout functionality and can be extended for additional auth features.
 */
export function useAuth() {
    const logout = () => {
        // Clear authentication tokens from storage
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');

        // Optional: Clear any other auth-related data
        sessionStorage.clear();
    };

    return {
        logout,
    };
}
