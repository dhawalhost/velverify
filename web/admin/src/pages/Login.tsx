import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { login, getBranding, completeMfaLogin, lookupUser, beginLogin, finishLogin, getSetupStatus } from '../api';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ShieldCheck, Fingerprint, ArrowRight, User as UserIcon, Lock } from 'lucide-react';
import { startAuthentication } from '@simplewebauthn/browser';

const Login: React.FC = () => {
    const policyBaseUrl = window.location.hostname.endsWith('.local')
        ? 'http://wardseal.local'
        : 'https://wardseal.com';

    const getDeviceID = () => {
        let deviceID = localStorage.getItem('deviceID');
        if (!deviceID) {
            deviceID = crypto.randomUUID();
            localStorage.setItem('deviceID', deviceID);
        }
        return deviceID;
    };

    const navigate = useNavigate();
    const [searchParams] = useSearchParams();

    // Config State
    const [tenantID, setTenantID] = useState(() => {
        return searchParams.get('tenant') || '';
    });

    const [branding, setBranding] = useState<{
        logo_url?: string;
        primary_color?: string;
        background_color?: string;
        css_override?: string;
    }>({});

    // Login Flow State
    const [step, setStep] = useState<'identifier' | 'challenge'>('identifier');
    const [email, setEmail] = useState('');
    const [userID, setUserID] = useState('');
    const [webAuthnEnabled, setWebAuthnEnabled] = useState(false);
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    // MFA State
    const [mfaRequired, setMfaRequired] = useState(false);
    const [pendingToken, setPendingToken] = useState('');
    const [mfaUserId, setMfaUserId] = useState('');
    const [totpCode, setTotpCode] = useState('');

    const fetchBranding = async (tid: string) => {
        if (!tid) return;
        try {
            const config = await getBranding(tid);
            setBranding(config);
            if (config.css_override) {
                const style = document.createElement('style');
                style.innerHTML = config.css_override;
                document.head.appendChild(style);
            }
        } catch (err) {
            console.log("Using default branding/tenant not found");
            setBranding({});
        }
    };

    useEffect(() => {
        // Check if system needs initial setup
        const checkSetupStatus = async () => {
            try {
                const status = await getSetupStatus();
                if (status.setup_required) {
                    navigate('/setup');
                }
            } catch (err) {
                // If check fails, assume no setup needed (might be network issue)
                console.error("Failed to check setup status", err);
            }
        };
        checkSetupStatus();
    }, [navigate]);

    useEffect(() => {
        if (tenantID) {
            fetchBranding(tenantID);
            localStorage.setItem('tenantID', tenantID);
        }
    }, [tenantID]);


    const performRedirection = (data: any) => {
        const redirectUri = searchParams.get('redirect_uri');
        console.log('Performing redirection. redirectUri:', redirectUri, 'data:', data);

        if (redirectUri) {
            // Explicitly handle relative paths by using window.location for full page transition
            if (redirectUri.startsWith('/')) {
                window.location.assign(window.location.origin + redirectUri);
            } else {
                window.location.href = redirectUri;
            }
            return;
        }

        // Role-based redirection fallback
        const roles = data.roles || [];
        if (roles.includes('admin')) {
            navigate('/dashboard');
        } else {
            navigate('/portal');
        }
    };

    const handleIdentifierSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        // Tenant ID is optional now (backend discovery)
        // If provided, we save it. If not, backend returns it.
        if (tenantID) {
            localStorage.setItem('tenantID', tenantID);
        } else {
            localStorage.removeItem('tenantID'); // Ensure clean slate if empty
        }

        if (!email) {
            setError('Email is required');
            setLoading(false);
            return;
        }

        try {
            // Lookup User
            const lookup = await lookupUser(email);
            setUserID(lookup.user_id);
            setWebAuthnEnabled(lookup.webauthn_enabled);

            // If tenant was discovered, save it
            if (lookup.tenant_id) {
                setTenantID(lookup.tenant_id);
                localStorage.setItem('tenantID', lookup.tenant_id);
            }
            if (lookup.tenant_slug) {
                localStorage.setItem('tenantSlug', lookup.tenant_slug);
            }

            setStep('challenge');

        } catch (err: any) {
            console.error(err);
            if (err.response?.status === 404) {
                setError("Account not found");
            } else {
                setError('Failed to find account');
            }
        } finally {
            setLoading(false);
        }
    };

    const handlePasswordLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            const deviceID = getDeviceID();

            // Attempt to get High Entropy OS Version (overcoming User-Agent Reduction)
            let osVersion = undefined;
            if ((navigator as any).userAgentData && (navigator as any).userAgentData.getHighEntropyValues) {
                try {
                    const uaValues = await (navigator as any).userAgentData.getHighEntropyValues(['platformVersion']);
                    if (uaValues.platformVersion) {
                        osVersion = uaValues.platformVersion;
                    }
                } catch (e) {
                    console.warn("Failed to get high entropy values", e);
                }
            }

            const data = await login(email, password, deviceID, osVersion);

            // MFA Check
            if (data.mfa_required) {
                setMfaRequired(true);
                setPendingToken(data.pending_token);
                setMfaUserId(data.user_id);
                setLoading(false);
                return;
            }

            localStorage.setItem('token', data.token);
            localStorage.setItem('userId', email);
            if (data.tenant_id) {
                localStorage.setItem('tenantID', data.tenant_id);
            }
            if (data.tenant_slug) {
                localStorage.setItem('tenantSlug', data.tenant_slug);
            }

            performRedirection(data);
        } catch (err: any) {
            console.error(err);
            // Ensure tenantID is still set if login fails (it should be from step 1)
            setError(err.response?.data?.error_description || 'Invalid credentials');
        } finally {
            setLoading(false);
        }
    };

    const handlePasskeyLogin = async () => {
        setError('');
        setLoading(true);
        try {
            // 1. Begin Login
            const options = await beginLogin(userID);

            // 2. Browser Prompt
            const creds = await startAuthentication(options);

            // 3. Finish Login
            const data = await finishLogin(userID, creds);

            localStorage.setItem('token', data.token);
            localStorage.setItem('userId', email);
            if (data.tenant_id) {
                localStorage.setItem('tenantID', data.tenant_id);
            }
            if (data.tenant_slug) {
                localStorage.setItem('tenantSlug', data.tenant_slug);
            }

            performRedirection(data);
        } catch (err: any) {
            console.error(err);
            setError('Passkey authentication failed');
            setLoading(false);
        }
    };

    const handleMfaSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            const data = await completeMfaLogin(pendingToken, totpCode, mfaUserId);
            localStorage.setItem('token', data.token);
            localStorage.setItem('userId', email);
            if (data.tenant_id) {
                localStorage.setItem('tenantID', data.tenant_id);
            }
            if (data.tenant_slug) {
                localStorage.setItem('tenantSlug', data.tenant_slug);
            }

            performRedirection(data);
        } catch (err: any) {
            console.error(err);
            setError('Invalid TOTP code');
            setLoading(false);
        }
    };

    // --- RENDER ---

    if (mfaRequired) {
        return (
            <div className="flex items-center justify-center min-h-screen bg-muted/20 p-4">
                <Card className="w-full max-w-md shadow-lg border-muted/40 font-inter">
                    <CardHeader className="text-center">
                        <div className="mx-auto w-16 h-16 flex items-center justify-center mb-4">
                            <img src="/wardseal.svg" alt="Logo" className="w-full h-full object-contain" />
                        </div>
                        <CardTitle>Verify identity</CardTitle>
                        <CardDescription>Enter code from authenticator app</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form onSubmit={handleMfaSubmit} className="space-y-4">
                            <Input
                                value={totpCode}
                                onChange={(e) => setTotpCode(e.target.value)}
                                placeholder="000000"
                                className="text-center text-2xl tracking-widest font-mono"
                                maxLength={6}
                                autoFocus
                            />
                            {error && <p className="text-sm text-destructive text-center">{error}</p>}
                            <Button type="submit" className="w-full" disabled={loading}>
                                {loading ? 'Verifying...' : 'Verify'}
                            </Button>
                        </form>
                    </CardContent>
                </Card>
            </div>
        )
    }

    return (
        <div className="flex items-center justify-center min-h-screen bg-muted/20 p-4 transition-colors duration-500" style={{ backgroundColor: branding.background_color }}>
            <Card className="w-full max-w-md shadow-lg border-muted/40 animate-in fade-in zoom-in duration-300">
                <CardHeader className="text-center pb-6">
                    {branding.logo_url ? (
                        <img src={branding.logo_url} alt="Logo" className="mx-auto h-12 mb-4 object-contain" />
                    ) : (
                        <div className="mx-auto w-24 h-24 flex items-center justify-center mb-4">
                            <img src="/wardseal.svg" alt="WardSeal" className="w-full h-full object-contain" />
                        </div>
                    )}
                    <CardTitle className="text-2xl font-bold tracking-tight">
                        {branding.logo_url ? 'Sign In' : 'WardSeal Identity'}
                    </CardTitle>
                    {step === 'identifier' && (
                        <CardDescription>Enter your email to continue</CardDescription>
                    )}
                    {step === 'challenge' && (
                        <div className="flex flex-col items-center mt-2 space-y-2">
                            <div className="bg-muted px-3 py-1 rounded-full text-xs font-medium flex items-center gap-2">
                                <UserIcon className="w-3 h-3" />
                                {email}
                                <span className="text-muted-foreground cursor-pointer hover:text-foreground ml-1" onClick={() => setStep('identifier')}>(Change)</span>
                            </div>
                        </div>
                    )}
                </CardHeader>
                <CardContent>
                    {step === 'identifier' ? (
                        <form onSubmit={handleIdentifierSubmit} className="space-y-4">
                            <div className="space-y-2">
                                <Label htmlFor="email">Email address</Label>
                                <Input
                                    id="email"
                                    type="email"
                                    placeholder="name@company.com"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    required
                                    autoFocus
                                />
                            </div>

                            {/* Tenant ID Field - Hidden/Optional now */}
                            {searchParams.get('debug') === 'true' && (
                                <div className="space-y-2">
                                    <Label htmlFor="tenant" className="text-muted-foreground text-xs font-normal">Tenant (Optional)</Label>
                                    <Input
                                        id="tenant"
                                        placeholder="e.g. default"
                                        value={tenantID}
                                        onChange={(e) => setTenantID(e.target.value)}
                                        className="bg-muted/30"
                                    />
                                </div>
                            )}

                            {error && <div className="p-3 text-sm bg-destructive/10 text-destructive rounded-md flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> {error}</div>}
                            <Button type="submit" className="w-full" disabled={loading}>
                                {loading ? 'Next...' : 'Next'} <ArrowRight className="ml-2 w-4 h-4" />
                            </Button>
                        </form>
                    ) : (
                        <div className="space-y-4">
                            {/* Passkey Option (Primary if enabled) */}
                            {webAuthnEnabled && (
                                <Button
                                    type="button"
                                    variant="outline"
                                    className="w-full h-12 text-base border-primary/20 hover:bg-primary/5 hover:border-primary/50 transition-all text-foreground"
                                    onClick={handlePasskeyLogin}
                                    disabled={loading}
                                >
                                    <Fingerprint className="mr-2 h-5 w-5 text-primary" />
                                    Sign in with Passkey
                                </Button>
                            )}

                            {webAuthnEnabled && (
                                <div className="relative my-4">
                                    <div className="absolute inset-0 flex items-center">
                                        <span className="w-full border-t" />
                                    </div>
                                    <div className="relative flex justify-center text-xs uppercase">
                                        <span className="bg-background px-2 text-muted-foreground">
                                            Or
                                        </span>
                                    </div>
                                </div>
                            )}

                            {/* Password Form */}
                            <form onSubmit={handlePasswordLogin} className="space-y-4">
                                <div className="space-y-2">
                                    <div className="flex justify-between items-center">
                                        <Label htmlFor="password">Password</Label>
                                        <a href="#" className="text-xs text-primary hover:underline">Forgot?</a>
                                    </div>
                                    <Input
                                        id="password"
                                        type="password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        required
                                        autoFocus={!webAuthnEnabled}
                                    />
                                </div>
                                {error && <div className="p-3 text-sm bg-destructive/10 text-destructive rounded-md flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> {error}</div>}
                                <Button type="submit" className="w-full" disabled={loading}>
                                    {loading ? 'Verifying...' : 'Sign In with Password'}
                                </Button>
                            </form>
                        </div>
                    )}
                </CardContent>
                <CardFooter className="flex flex-col gap-2">
                    <p className="text-center text-xs text-muted-foreground w-full">
                        Protected by WardSeal Identity
                    </p>
                    <p className="text-center text-xs text-muted-foreground w-full">
                        New here? <a href="/signup" className="text-primary hover:underline">Create an account</a>
                    </p>
                    <p className="text-center text-xs text-muted-foreground w-full flex items-center justify-center gap-3">
                        <a href={`${policyBaseUrl}/policies#privacy`} target="_blank" rel="noreferrer" className="text-primary hover:underline">Privacy</a>
                        <a href={`${policyBaseUrl}/policies#privacy`} target="_blank" rel="noreferrer" className="text-primary hover:underline">Terms</a>
                        <a href={`${policyBaseUrl}/policies`} target="_blank" rel="noreferrer" className="text-primary hover:underline">Policies</a>
                    </p>
                </CardFooter>
            </Card>
        </div>
    );
};

export default Login;
