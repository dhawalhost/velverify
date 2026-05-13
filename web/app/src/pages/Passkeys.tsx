import React, { useState } from 'react';
import { beginRegistration, finishRegistration } from '../api';
import { startRegistration } from '@simplewebauthn/browser';
import { Button } from '@/components/ui/button';
import { Fingerprint, Loader2, Check, AlertTriangle } from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassCardDescription } from '@/components/layout';

const Passkeys: React.FC = () => {
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');
    const [isRegistering, setIsRegistering] = useState(false);

    // Helper to decode JWT
    const getUserID = () => {
        const token = localStorage.getItem('token');
        if (!token) return null;
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function (c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
            return JSON.parse(jsonPayload).sub;
        } catch (e) {
            return null;
        }
    };

    const handleRegister = async () => {
        setMessage('');
        setError('');
        setIsRegistering(true);
        const userID = getUserID();
        if (!userID) {
            setError('User ID not found. Please log in again.');
            setIsRegistering(false);
            return;
        }

        try {
            // 1. Begin
            const options = await beginRegistration(userID);

            // 2. Browser Prompt
            const attResp = await startRegistration(options);

            // 3. Finish
            await finishRegistration(userID, attResp);

            setMessage('Passkey registered successfully! You can now use it to log in securely without a password.');
        } catch (err: any) {
            console.error(err);
            setError(err.response?.data?.error || err.message || 'Registration failed. Your device might not support passkeys or cancelled the request.');
        } finally {
            setIsRegistering(false);
        }
    };

    return (
        <div className="space-y-12 max-w-2xl mx-auto animate-in fade-in duration-700">
            <PageHeader
                icon={<Fingerprint className="w-10 h-10 text-primary" />}
                title="Passkeys"
                description="Go passwordless with biometric authentication. Use TouchID, FaceID, or a hardware security key."
            />

            <GlassCard className="border-none shadow-2xl shadow-on-surface/5 overflow-hidden rounded-[32px] bg-card">
                <GlassCardHeader className="bg-primary py-14 px-10 text-white relative overflow-hidden">
                    <div className="absolute top-0 right-0 opacity-10 p-8">
                        <Fingerprint className="w-40 h-40 -mr-10 -mt-10" />
                    </div>
                    <div className="relative z-10 flex flex-col items-center text-center gap-6">
                        <div className="w-20 h-20 bg-card/20 rounded-3xl flex items-center justify-center backdrop-blur-md shadow-inner">
                            <Fingerprint className="w-10 h-10 text-white" />
                        </div>
                        <div>
                            <GlassCardTitle className="text-3xl font-bold tracking-tight text-white">Register a Passkey</GlassCardTitle>
                            <GlassCardDescription className="text-on-inverse/60 font-medium text-sm mt-3 max-w-sm mx-auto leading-relaxed">
                                Use TouchID, FaceID, or a hardware security key (YubiKey) to sign in faster and more securely.
                            </GlassCardDescription>
                        </div>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-10 space-y-8">
                    {message && (
                        <div className="bg-success-subtle border border-success/20 text-success p-5 rounded-2xl flex items-center gap-3 font-bold text-sm animate-in slide-in-from-bottom-4">
                            <Check className="h-5 w-5 shrink-0" />
                            {message}
                        </div>
                    )}
                    {error && (
                        <div className="bg-destructive/10 border border-destructive/20 text-destructive p-5 rounded-2xl flex items-center gap-3 font-bold text-sm animate-in slide-in-from-bottom-4">
                            <AlertTriangle className="h-5 w-5 shrink-0" />
                            {error}
                        </div>
                    )}

                    <Button
                        onClick={handleRegister}
                        size="lg"
                        className="w-full h-16 rounded-2xl text-base font-bold tracking-tight shadow-xl shadow-primary/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
                        disabled={isRegistering}
                    >
                        {isRegistering ? (
                            <>
                                <Loader2 className="mr-3 h-5 w-5 animate-spin" /> Waiting for device...
                            </>
                        ) : (
                            <>
                                <Fingerprint className="mr-3 h-5 w-5" /> Register Passkey
                            </>
                        )}
                    </Button>
                    <p className="text-xs text-center text-on-surface-variant/40 font-medium">
                        Supported on modern browsers (Chrome, Safari, Edge, Firefox) on macOS, Windows, iOS, and Android.
                    </p>
                </GlassCardContent>
            </GlassCard>
        </div>
    );
};

export default Passkeys;
