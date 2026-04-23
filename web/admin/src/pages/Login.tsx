import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { login, getBranding, completeMfaLogin, lookupUser, beginLogin, finishLogin, getSetupStatus, getUserRoles } from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ShieldCheck, Fingerprint, ArrowRight, User as UserIcon, Lock, Activity, ShieldAlert, MoreHorizontal, Loader2 } from 'lucide-react';
import { startAuthentication } from '@simplewebauthn/browser';
import { v4 as uuidv4 } from 'uuid';
import {
    GlassCard,
    GlassCardHeader,
    GlassCardTitle,
    GlassCardContent,
    GlassCardDescription
} from '@/components/layout';

const ADMIN_ROLE = 'admin';

type TokenPayload = {
    sub?: string;
    user_id?: string;
    roles?: string[];
    role?: string;
};

type RBACRole = {
    id?: string;
    name?: string;
};

const decodeTokenPayload = (token: string | null): TokenPayload | null => {
    if (!token) return null;

    try {
        const [, payload] = token.split('.');
        if (!payload) return null;

        const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
        const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
        return JSON.parse(atob(padded));
    } catch {
        return null;
    }
};

const getTokenUserID = (token: string | null): string => {
    const payload = decodeTokenPayload(token);
    if (!payload) return '';
    return payload.sub || payload.user_id || '';
};

const Login: React.FC = () => {
    const policyBaseUrl = window.location.hostname.endsWith('.local')
        ? 'http://wardseal.local'
        : 'https://wardseal.com';

    const getDeviceID = () => {
        let deviceID = localStorage.getItem('deviceID');
        if (!deviceID) {
            deviceID = uuidv4();
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
        const checkSetupStatus = async () => {
            try {
                const status = await getSetupStatus();
                if (status.setup_required) {
                    navigate('/setup');
                }
            } catch (err) {
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


    const performRedirection = async () => {
        const redirectUri = searchParams.get('redirect_uri');
        if (redirectUri) {
            if (redirectUri.startsWith('/')) {
                window.location.assign(window.location.origin + redirectUri);
            } else {
                window.location.href = redirectUri;
            }
            return;
        }
        navigate('/portal');
    };

    const handleIdentifierSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        if (tenantID) {
            localStorage.setItem('tenantID', tenantID);
        } else {
            localStorage.removeItem('tenantID');
        }

        if (!email) {
            setError('Email is required');
            setLoading(false);
            return;
        }

        try {
            const lookup = await lookupUser(email);
            setUserID(lookup.user_id);
            setWebAuthnEnabled(lookup.webauthn_enabled);

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

            if (data.mfa_required) {
                setMfaRequired(true);
                setPendingToken(data.pending_token);
                setMfaUserId(data.user_id);
                setLoading(false);
                return;
            }

            localStorage.setItem('token', data.token);
            const tokenUserID = getTokenUserID(data.token) || email;
            localStorage.setItem('userId', tokenUserID);
            if (data.tenant_id) {
                localStorage.setItem('tenantID', data.tenant_id);
            }
            if (data.tenant_slug) {
                localStorage.setItem('tenantSlug', data.tenant_slug);
            }

            await performRedirection();
        } catch (err: any) {
            console.error(err);
            setError(err.response?.data?.error_description || 'Invalid credentials');
        } finally {
            setLoading(false);
        }
    };

    const handlePasskeyLogin = async () => {
        setError('');
        setLoading(true);
        try {
            const options = await beginLogin(userID);
            const creds = await startAuthentication(options);
            const data = await finishLogin(userID, creds);

            localStorage.setItem('token', data.token);
            const tokenUserID = getTokenUserID(data.token) || email;
            localStorage.setItem('userId', tokenUserID);
            if (data.tenant_id) {
                localStorage.setItem('tenantID', data.tenant_id);
            }
            if (data.tenant_slug) {
                localStorage.setItem('tenantSlug', data.tenant_slug);
            }

            await performRedirection();
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
            const tokenUserID = getTokenUserID(data.token) || email;
            localStorage.setItem('userId', tokenUserID);
            if (data.tenant_id) {
                localStorage.setItem('tenantID', data.tenant_id);
            }
            if (data.tenant_slug) {
                localStorage.setItem('tenantSlug', data.tenant_slug);
            }

            await performRedirection();
        } catch (err: any) {
            console.error(err);
            setError('Invalid TOTP code');
            setLoading(false);
        }
    };

    if (mfaRequired) {
        return (
            <div className="flex items-center justify-center min-h-screen bg-slate-50 px-6">
                <GlassCard className="w-full max-w-[400px] border-none shadow-2xl bg-white overflow-hidden animate-in zoom-in duration-500">
                    <GlassCardHeader className="pt-12 pb-6 px-10 text-center">
                        <div className="mx-auto w-9 h-9 bg-primary rounded-[14px] flex items-center justify-center mb-6 shadow-sm">
                            <ShieldCheck className="w-5 h-5 text-white" />
                        </div>
                        <GlassCardTitle className="text-2xl font-bold tracking-tight">Security verification</GlassCardTitle>
                        <GlassCardDescription className="text-[11px] font-bold uppercase tracking-widest mt-2 opacity-50">Multi-factor authentication required</GlassCardDescription>
                    </GlassCardHeader>
                    <GlassCardContent className="px-10 pb-12">
                        <form onSubmit={handleMfaSubmit} className="space-y-8">
                            <div className="space-y-4 text-center">
                                <Label className="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant/40 ml-1">Authentication code</Label>
                                <Input
                                    value={totpCode}
                                    onChange={(e) => setTotpCode(e.target.value)}
                                    placeholder="000 000"
                                    className="h-16 text-center text-4xl font-black tracking-[0.2em] border-none bg-surface-container/30 rounded-2xl focus-visible:ring-2 focus-visible:ring-primary/20"
                                    maxLength={6}
                                    autoFocus
                                />
                            </div>
                            {error && (
                                <div className="p-4 bg-red-50 text-red-600 rounded-xl flex items-center gap-3 border border-red-100 animate-in fade-in slide-in-from-top-2">
                                    <ShieldAlert className="w-5 h-5 shrink-0" />
                                    <span className="text-xs font-bold uppercase tracking-tight">{error}</span>
                                </div>
                            )}
                            <Button type="submit" className="w-full h-14 rounded-2xl font-black text-xs uppercase tracking-widest shadow-lg shadow-primary/20 transition-all" disabled={loading}>
                                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Verify Access'}
                            </Button>
                        </form>
                    </GlassCardContent>
                </GlassCard>
            </div>
        )
    }

    return (
        <div className="flex min-h-screen bg-white font-sans selection:bg-primary/10">
            {/* Left Side: Brand & Visual */}
            <div className="hidden lg:flex lg:w-1/2 relative bg-[#0f172a] overflow-hidden flex-col justify-between p-16">
                {/* Abstract Pattern / Background */}
                <div className="absolute inset-0 opacity-20 pointer-events-none">
                    <div className="absolute -top-[10%] -left-[10%] w-[60%] h-[60%] bg-primary rounded-full blur-[120px]" />
                    <div className="absolute -bottom-[10%] -right-[10%] w-[60%] h-[60%] bg-indigo-500 rounded-full blur-[120px]" />
                </div>

                <div className="relative z-10">
                    <div className="flex items-center gap-3 group">
                        <div className="w-10 h-10 flex items-center justify-center">
                            <img src="/wardseal.svg" alt="WardSeal" className="w-full h-full object-contain" />
                        </div>
                        <span className="text-2xl font-bold tracking-tight text-white group-hover:opacity-80 transition-opacity">WardSeal</span>
                    </div>
                </div>

                <div className="relative z-10 max-w-md">
                    <h1 className="text-5xl font-bold tracking-tight leading-[1.1] text-white mb-6">
                        Enterprise identity for <br />
                        <span className="text-primary-foreground/60 italic">modern workspaces.</span>
                    </h1>
                    <p className="text-lg text-slate-400 font-medium leading-relaxed">
                        Secure your organizational infrastructure with the industry standard for OIDC, SAML, and Adaptive MFA.
                    </p>
                </div>

                <div className="relative z-10 flex items-center gap-10 opacity-40 grayscale group hover:grayscale-0 hover:opacity-100 transition-all duration-700">
                    <div className="text-white font-bold text-xs tracking-widest uppercase">Trusted by</div>
                    <div className="flex gap-8">
                        <div className="h-6 w-24 bg-white/10 rounded-md" />
                        <div className="h-6 w-24 bg-white/10 rounded-md" />
                    </div>
                </div>
            </div>

            {/* Right Side: Authentication Form */}
            <div className="w-full lg:w-1/2 flex flex-col justify-center px-8 sm:px-12 lg:px-24 xl:px-32 py-12">
                <div className="w-full max-w-md mx-auto">
                    {/* Mobile Logo Only */}
                    <div className="lg:hidden mb-12 flex justify-center">
                        <img src="/wardseal.svg" alt="WardSeal" className="w-12 h-12" />
                    </div>

                    <div className="mb-10 text-center lg:text-left">
                        <h2 className="text-3xl font-bold tracking-tight text-slate-900">
                            {step === 'identifier' ? 'Welcome back' : 'Verify identity'}
                        </h2>
                        <p className="text-slate-500 font-medium mt-2">
                            {step === 'identifier' 
                                ? 'Please enter your credentials to continue' 
                                : `Authentication required for ${email}`}
                        </p>
                    </div>

                    {step === 'identifier' ? (
                        <form onSubmit={handleIdentifierSubmit} className="space-y-6">
                            <div className="space-y-2">
                                <Label htmlFor="email" className="text-sm font-semibold text-slate-700 ml-1">Email address</Label>
                                <div className="relative group">
                                    <UserIcon className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-300 group-focus-within:text-primary transition-colors" />
                                    <Input
                                        id="email"
                                        type="email"
                                        placeholder="name@company.com"
                                        className="h-14 pl-12 rounded-xl border-slate-200 bg-slate-50/50 focus:bg-white focus:ring-2 focus:ring-primary/10 focus:border-primary transition-all text-base"
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        required
                                        autoFocus
                                    />
                                </div>
                            </div>

                            {error && (
                                <div className="p-4 bg-red-50 text-red-600 rounded-xl flex items-center gap-3 border border-red-100">
                                    <ShieldAlert className="w-5 h-5 shrink-0" />
                                    <span className="text-xs font-bold uppercase tracking-tight">{error}</span>
                                </div>
                            )}

                            <Button type="submit" className="w-full h-14 rounded-xl bg-primary text-white font-bold text-base shadow-lg shadow-primary/20 hover:shadow-primary/30 transition-all hover:-translate-y-0.5 active:translate-y-0 group" disabled={loading}>
                                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : (
                                    <>Continue <ArrowRight className="ml-2 w-5 h-5 group-hover:translate-x-1 transition-transform" /></>
                                )}
                            </Button>
                        </form>
                    ) : (
                        <div className="space-y-6">
                            {webAuthnEnabled && (
                                <Button
                                    type="button"
                                    className="w-full h-14 rounded-xl border-none bg-primary/5 text-primary hover:bg-primary/10 transition-all font-bold flex items-center justify-center gap-3"
                                    onClick={handlePasskeyLogin}
                                    disabled={loading}
                                >
                                    <Fingerprint className="w-5 h-5" />
                                    Sign in with Passkey
                                </Button>
                            )}

                            {webAuthnEnabled && (
                                <div className="relative py-2">
                                    <div className="absolute inset-0 flex items-center">
                                        <span className="w-full border-t border-slate-100" />
                                    </div>
                                    <div className="relative flex justify-center text-[10px] font-bold uppercase tracking-widest">
                                        <span className="bg-white px-4 text-slate-400">or use password</span>
                                    </div>
                                </div>
                            )}

                            <form onSubmit={handlePasswordLogin} className="space-y-6">
                                <div className="space-y-2">
                                    <div className="flex justify-between items-center px-1">
                                        <Label htmlFor="password" className="text-sm font-semibold text-slate-700">Password</Label>
                                        <button type="button" onClick={() => setStep('identifier')} className="text-xs font-bold text-primary hover:opacity-70 transition-opacity">Change email</button>
                                    </div>
                                    <div className="relative group">
                                        <Lock className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-300 group-focus-within:text-primary transition-colors" />
                                        <Input
                                            id="password"
                                            type="password"
                                            placeholder="••••••••"
                                            className="h-14 pl-12 rounded-xl border-slate-200 bg-slate-50/50 focus:bg-white focus:ring-2 focus:ring-primary/10 focus:border-primary transition-all text-base"
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                            required
                                            autoFocus={!webAuthnEnabled}
                                        />
                                    </div>
                                </div>

                                {error && (
                                    <div className="p-4 bg-red-50 text-red-600 rounded-xl flex items-center gap-3 border border-red-100">
                                        <ShieldAlert className="w-5 h-5 shrink-0" />
                                        <span className="text-xs font-bold uppercase tracking-tight">{error}</span>
                                    </div>
                                )}

                                <Button type="submit" className="w-full h-14 rounded-xl bg-primary text-white font-bold text-base shadow-lg shadow-primary/20 hover:shadow-primary/30 transition-all hover:-translate-y-0.5" disabled={loading}>
                                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Confirm Identity'}
                                </Button>
                            </form>
                        </div>
                    )}

                    <div className="mt-12 text-center">
                        <p className="text-sm font-medium text-slate-500">
                            Don't have an account? <a href="/signup" className="text-primary font-bold hover:underline decoration-2 underline-offset-4">Get started</a>
                        </p>
                    </div>

                    <div className="mt-24 pt-8 border-t border-slate-100 flex justify-center gap-8">
                        <a href={`${policyBaseUrl}/policies#privacy`} target="_blank" rel="noreferrer" className="text-xs font-bold text-slate-400 hover:text-slate-600 transition-colors">Privacy</a>
                        <a href={`${policyBaseUrl}/policies#terms`} target="_blank" rel="noreferrer" className="text-xs font-bold text-slate-400 hover:text-slate-600 transition-colors">Terms</a>
                        <a href={`${policyBaseUrl}/support`} target="_blank" rel="noreferrer" className="text-xs font-bold text-slate-400 hover:text-slate-600 transition-colors">Support</a>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Login;
