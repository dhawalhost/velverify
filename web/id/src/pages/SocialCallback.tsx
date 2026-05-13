import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { socialLogin } from '../api';
import { Loader2, AlertCircle } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

const SocialCallback: React.FC = () => {
    const [error, setError] = useState<string | null>(null);
    const navigate = useNavigate();
    const location = useLocation();

    useEffect(() => {
        const handleCallback = async () => {
            const params = new URLSearchParams(location.search);
            const code = params.get('code');
            const state = params.get('state');

            if (!code || !state) {
                setError('Missing code or state from provider');
                return;
            }

            // Parse state: tenant:ID:provider:NAME
            const stateParts = state.split(':');
            let tenantID = '';
            let provider = '';
            
            if (stateParts.length >= 4) {
                tenantID = stateParts[1];
                provider = stateParts[3];
            }

            if (!tenantID || !provider) {
                setError('Invalid state returned from provider');
                return;
            }

            try {
                // Construct redirectURI - must match what was sent to authorize
                const redirectURI = window.location.origin + window.location.pathname;
                
                const response = await socialLogin(provider, code, redirectURI);
                
                if (response.pending_token && response.error === 'mfa_required') {
                    // Redirect to MFA completion
                    navigate(`/login?step=mfa&pending_token=${response.pending_token}`);
                    return;
                }

                // Success! Tokens are set by axios interceptor/cookie
                // Redirect back to original target if stored, or profile
                const savedRedirect = localStorage.getItem('login_redirect_uri');
                if (savedRedirect) {
                    localStorage.removeItem('login_redirect_uri');
                    window.location.href = savedRedirect;
                } else {
                    navigate('/profile');
                }
            } catch (err: any) {
                console.error('Social login completion failed', err);
                setError(err.response?.data?.error || err.message || 'Failed to complete social login');
            }
        };

        handleCallback();
    }, [location, navigate]);

    if (error) {
        return (
            <div className="flex items-center justify-center min-h-screen p-6 bg-surface">
                <div className="w-full max-w-md">
                    <Alert variant="destructive" className="border-2 shadow-xl bg-card">
                        <AlertCircle className="h-5 w-5" />
                        <AlertTitle className="font-bold">Authentication Error</AlertTitle>
                        <AlertDescription className="mt-2 text-sm opacity-90">
                            {error}
                        </AlertDescription>
                    </Alert>
                    <button 
                        onClick={() => navigate('/login')}
                        className="w-full mt-6 py-3 px-4 bg-primary text-primary-foreground rounded-xl font-bold shadow-lg hover:shadow-primary/20 transition-all"
                    >
                        Return to Login
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="flex flex-col items-center justify-center min-h-screen bg-surface space-y-6">
            <div className="relative">
                <div className="absolute inset-0 bg-primary/20 blur-3xl rounded-full" />
                <Loader2 className="w-16 h-16 animate-spin text-primary relative z-10" />
            </div>
            <div className="text-center space-y-2">
                <h2 className="text-2xl font-bold tracking-tight">Completing Login</h2>
                <p className="text-muted-foreground animate-pulse">Syncing with your identity provider...</p>
            </div>
        </div>
    );
};

export default SocialCallback;
