import React, { useState } from 'react';
import { useNavigate, Link, useSearchParams } from 'react-router-dom';
import { signup } from '../api';
import Config from '../config';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ShieldCheck, ArrowRight, Building, Lock, Mail, Users, Check, Loader2, ShieldAlert, Fingerprint, Activity } from 'lucide-react';
import {
    GlassCard,
    GlassCardHeader,
    GlassCardTitle,
    GlassCardContent,
    GlassCardDescription
} from '@/components/layout';

const SignUp: React.FC = () => {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const policyBaseUrl = window.location.hostname.endsWith('.local')
        ? 'http://wardseal.local'
        : 'https://wardseal.com';
    const [companyName, setCompanyName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const plan = searchParams.get('plan') || 'free';

    if (!Config.features.publicSignup) {
        return (
            <div className="flex items-center justify-center min-h-screen bg-background p-4">
                <GlassCard className="w-full max-w-md shadow-2xl border-none bg-card text-center p-12">
                    <div className="mx-auto w-9 h-9 flex items-center justify-center bg-on-surface/5 rounded-[14px] mb-8">
                        <Lock className="w-5 h-5 text-on-surface/20" />
                    </div>
                    <GlassCardTitle className="mb-4 text-2xl font-bold tracking-tight">Registration disabled</GlassCardTitle>
                    <GlassCardDescription className="mb-10 text-[11px] font-bold uppercase tracking-widest leading-relaxed opacity-60">
                        Public registration is currently disabled on this server.
                    </GlassCardDescription>
                    <Button variant="outline" className="h-12 px-8 rounded-xl font-bold text-xs uppercase tracking-widest border-2 transition-all" onClick={() => navigate('/login')}>
                        Return to login
                    </Button>
                </GlassCard>
            </div>
        );
    }

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const data = await signup(email, password, companyName, plan);
            localStorage.setItem('token', data.token);
            localStorage.setItem('tenantID', data.tenant_id);
            if (data.tenant_slug) {
                localStorage.setItem('tenantSlug', data.tenant_slug);
            }
            localStorage.setItem('userId', email);
            navigate('/dashboard');
        } catch (err: any) {
            console.error(err);
            if (err.response?.status === 409) {
                setError("Domain segment already assigned.");
            } else {
                setError(err.response?.data?.error_description || err.response?.data?.error || 'Initialization failed.');
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex min-h-screen bg-card font-sans selection:bg-primary/10">
            {/* Left Side: Brand & Visual */}
            <div className="hidden lg:flex lg:w-1/2 relative bg-surface-container-high overflow-hidden flex-col justify-between p-16">
                {/* Abstract Pattern / Background */}
                <div className="absolute inset-0 opacity-20 pointer-events-none">
                    <div className="absolute -top-[10%] -right-[10%] w-[60%] h-[60%] bg-primary rounded-full blur-[120px]" />
                    <div className="absolute -bottom-[10%] -left-[10%] w-[60%] h-[60%] bg-indigo-500 rounded-full blur-[120px]" />
                </div>

                <div className="relative z-10">
                    <Link to="/" className="flex items-center gap-3 group">
                        <div className="w-10 h-10 flex items-center justify-center">
                            <img src="/wardseal.svg" alt="WardSeal" className="w-full h-full object-contain" />
                        </div>
                        <span className="text-2xl font-bold tracking-tight text-white group-hover:opacity-80 transition-opacity">WardSeal</span>
                    </Link>
                </div>

                <div className="relative z-10">
                    <h1 className="text-5xl font-bold tracking-tight leading-[1.1] text-white mb-8">
                        The foundation for <br />
                        <span className="text-primary-foreground/60 italic">modern identity trust.</span>
                    </h1>
                    <div className="space-y-6">
                        {[
                            { icon: <ShieldCheck className="w-5 h-5" />, text: "Enterprise SSO with OIDC & SAML 2.0" },
                            { icon: <Fingerprint className="w-5 h-5" />, text: "Passkey & Biometric Authentication" },
                            { icon: <Activity className="w-5 h-5" />, text: "Automated Governance & Access Reviews" }
                        ].map((item, i) => (
                            <div key={i} className="flex items-center gap-4 text-on-surface-variant/40">
                                <div className="p-2 bg-card/5 rounded-lg border border-on-inverse/10">{item.icon}</div>
                                <span className="text-base font-medium">{item.text}</span>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="relative z-10 flex items-center gap-10 opacity-40 grayscale group hover:grayscale-0 hover:opacity-100 transition-all duration-700">
                    <div className="text-white font-bold text-xs tracking-widest uppercase">Infrastructure for</div>
                    <div className="flex gap-8">
                        <div className="h-6 w-24 bg-card/10 rounded-md" />
                        <div className="h-6 w-24 bg-card/10 rounded-md" />
                    </div>
                </div>
            </div>

            {/* Right Side: Signup Form */}
            <div className="w-full lg:w-1/2 flex flex-col justify-center px-8 sm:px-12 lg:px-24 xl:px-32 py-12">
                <div className="w-full max-w-md mx-auto">
                    {/* Mobile Logo Only */}
                    <div className="lg:hidden mb-12 flex justify-center">
                        <img src="/wardseal.svg" alt="WardSeal" className="w-12 h-12" />
                    </div>

                    <div className="mb-10 text-center lg:text-left">
                        <h2 className="text-3xl font-bold tracking-tight text-on-surface">Create your account</h2>
                        <p className="text-on-surface-variant font-medium mt-2">Get started with your free organization</p>
                    </div>

                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="space-y-2">
                            <Label htmlFor="companyName" className="text-sm font-semibold text-on-surface ml-1">Company name</Label>
                            <div className="relative group">
                                <Building className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                                <Input
                                    id="companyName"
                                    placeholder="Acme Corp"
                                    className="h-14 pl-12 rounded-xl border-border bg-background/50 focus:bg-card focus:ring-2 focus:ring-primary/10 focus:border-primary transition-all text-base"
                                    value={companyName}
                                    onChange={(e) => setCompanyName(e.target.value)}
                                    required
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="email" className="text-sm font-semibold text-on-surface ml-1">Work email</Label>
                            <div className="relative group">
                                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                                <Input
                                    id="email"
                                    type="email"
                                    placeholder="name@company.com"
                                    className="h-14 pl-12 rounded-xl border-border bg-background/50 focus:bg-card focus:ring-2 focus:ring-primary/10 focus:border-primary transition-all text-base"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    required
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="password" className="text-sm font-semibold text-on-surface ml-1">Create password</Label>
                            <div className="relative group">
                                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                                <Input
                                    id="password"
                                    type="password"
                                    placeholder="••••••••"
                                    className="h-14 pl-12 rounded-xl border-border bg-background/50 focus:bg-card focus:ring-2 focus:ring-primary/10 focus:border-primary transition-all text-base"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    required
                                />
                            </div>
                        </div>

                        <Button type="submit" className="w-full h-14 rounded-xl bg-primary text-primary-foreground font-bold text-base shadow-lg shadow-primary/20 hover:shadow-primary/30 transition-all hover:-translate-y-0.5 active:translate-y-0 group" disabled={loading}>
                            {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : (
                                <>Create organization <ArrowRight className="ml-2 w-5 h-5 group-hover:translate-x-1 transition-transform" /></>
                            )}
                        </Button>
                    </form>

                    <div className="mt-12 text-center">
                        <p className="text-sm font-medium text-on-surface-variant">
                            Already have an account? <Link to="/login" className="text-primary font-bold hover:underline decoration-2 underline-offset-4">Sign in</Link>
                        </p>
                    </div>

                    <div className="mt-16 pt-8 border-t border-border flex justify-center gap-8">
                        <a href="#" className="text-xs font-bold text-on-surface-variant/40 hover:text-primary transition-colors">Privacy Policy</a>
                        <a href="#" className="text-xs font-bold text-on-surface-variant/40 hover:text-primary transition-colors">Terms of Service</a>
                        <a href="#" className="text-xs font-bold text-on-surface-variant/40 hover:text-primary transition-colors">Support</a>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default SignUp;
