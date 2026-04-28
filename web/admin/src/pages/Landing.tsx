import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
    ArrowRight, ShieldCheck, Lock, Globe, Zap, Server, Code, Check, X,
    Users, KeyRound, Fingerprint, BarChart3, Webhook, Building2,
    ChevronDown, ChevronUp, Star, ExternalLink, Github, Mail, Twitter,
    PlayCircle, Activity, Layout, Terminal, Cpu, Database
} from 'lucide-react';
import { ModeToggle } from '@/components/mode-toggle';
import { 
    GlassCard, 
    GlassCardHeader, 
    GlassCardTitle, 
    GlassCardContent,
    GlassCardDescription
} from '@/components/layout';

// ──────────────────────────────────────
// Sub-components
// ──────────────────────────────────────

const FeatureCard = ({ icon, title, description, category }: { icon: React.ReactNode; title: string; description: string; category?: string }) => (
    <GlassCard className="p-8 border-none bg-card shadow-xl shadow-on-surface/5 hover:shadow-primary/5 hover:scale-[1.02] transition-all duration-500 group relative overflow-hidden">
        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
            {icon}
        </div>
        <div className="mb-8 p-4 bg-primary/5 rounded-[1.5rem] w-fit group-hover:bg-primary/10 transition-colors">
            <div className="text-primary">{icon}</div>
        </div>
        {category && (
            <p className="text-[10px] font-bold tracking-tight text-primary mb-3 italic">{category.toLowerCase()}</p>
        )}
        <h3 className="text-xl font-bold tracking-tight mb-4 text-on-surface group-hover:translate-x-1 transition-transform">{title}</h3>
        <p className="text-on-surface-variant/60 font-medium text-sm leading-relaxed">{description}</p>
    </GlassCard>
);

const StepCard = ({ step, title, description }: { step: string; title: string; description: string }) => (
    <div className="flex gap-8 group">
        <div className="flex-shrink-0 w-12 h-12 rounded-2xl bg-on-surface/5 border border-on-surface/5 flex items-center justify-center text-on-surface/40 font-black text-xs group-hover:bg-primary group-hover:text-primary-foreground group-hover:border-primary transition-all duration-500">
            {step}
        </div>
        <div className="pt-1">
            <h3 className="font-bold tracking-tight text-lg mb-2 group-hover:text-primary transition-colors">{title}</h3>
            <p className="text-on-surface-variant/60 font-medium text-sm leading-relaxed max-w-sm">{description}</p>
        </div>
    </div>
);

const FaqItem = ({ question, answer }: { question: string; answer: string }) => {
    const [open, setOpen] = useState(false);
    return (
        <div className="border-b border-on-surface/5 last:border-0 overflow-hidden">
            <button className="w-full flex items-center justify-between py-8 text-left group gap-6" onClick={() => setOpen(o => !o)}>
                <span className="text-sm font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{question}</span>
                <div className={`p-2 rounded-xl transition-all duration-500 flex-shrink-0 ${open ? 'bg-primary text-primary-foreground rotate-180' : 'bg-on-surface/5 text-on-surface/20'}`}>
                    <ChevronDown className="w-4 h-4" />
                </div>
            </button>
            <div className={`transition-all duration-500 ease-in-out ${open ? 'max-h-96 pb-8 opacity-100' : 'max-h-0 opacity-0'}`}>
                <p className="text-on-surface-variant/60 font-medium text-sm leading-relaxed border-l-2 border-primary/20 pl-6 ml-4">
                    {answer}
                </p>
            </div>
        </div>
    );
};

const TestimonialCard = ({ quote, name, title, avatar }: { quote: string; name: string; title: string; avatar: string }) => (
    <GlassCard className="border-none bg-card shadow-xl shadow-on-surface/5 p-8 relative overflow-hidden">
        <div className="absolute -top-4 -right-4 w-24 h-24 bg-primary/5 rounded-full blur-2xl" />
        <div className="space-y-6 relative z-10">
            <div className="flex gap-1.5">
                {Array.from({ length: 5 }).map((_, i) => <Star key={i} className="w-3.5 h-3.5 fill-primary text-primary" />)}
            </div>
            <p className="text-lg font-bold italic tracking-tight text-on-surface leading-snug">"{quote}"</p>
            <div className="flex items-center gap-4 pt-4">
                <div className="w-10 h-10 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary font-black text-xs shadow-inner uppercase tracking-tighter">
                    {avatar}
                </div>
                <div>
                    <p className="text-sm font-bold tracking-tight text-on-surface">{name}</p>
                    <p className="text-[11px] font-medium text-on-surface-variant/40 italic">{title}</p>
                </div>
            </div>
        </div>
    </GlassCard>
);

// ──────────────────────────────────────
// Main Component
// ──────────────────────────────────────

const Landing: React.FC = () => {
    const navigate = useNavigate();
    const [billing, setBilling] = useState<'monthly' | 'yearly'>('monthly');

    const proPrice = billing === 'yearly' ? 23 : 29;
    const teamPrice = billing === 'yearly' ? 79 : 99;

    return (
        <div className="min-h-screen bg-background text-on-surface flex flex-col font-sans selection:bg-primary/20">
            {/* ── Header ──────────────────────────── */}
            <header className="px-6 lg:px-10 py-5 flex items-center justify-between border-b border-on-surface/5 backdrop-blur-xl sticky top-0 z-50 bg-card/70">
                {/* Logo */}
                <a href="/" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
                    <div className="w-9 h-9 flex items-center justify-center bg-primary rounded-[14px] shadow-sm">
                        <ShieldCheck className="w-5 h-5 text-white" />
                    </div>
                    <span className="font-bold text-lg tracking-tight text-on-surface">WardSeal</span>
                </a>

                <div className="flex items-center gap-10">
                    <nav className="hidden lg:flex gap-10 text-[13px] font-bold tracking-tight text-on-surface-variant/40">
                        <a href="#features" className="hover:text-primary transition-colors">Features</a>
                        <a href="#how-it-works" className="hover:text-primary transition-colors">How it works</a>
                        <a href="#pricing" className="hover:text-primary transition-colors">Pricing</a>
                    </nav>
                    
                    <div className="flex items-center gap-4">
                        <div className="hidden sm:flex items-center gap-2">
                            <Button variant="ghost" className="rounded-xl font-bold text-xs uppercase tracking-widest px-5 h-10 text-on-surface-variant/60 hover:text-primary" onClick={() => navigate('/login')}>
                                Sign in
                            </Button>
                            <Button className="rounded-xl font-bold text-xs uppercase tracking-widest px-6 h-10 shadow-lg shadow-primary/10" onClick={() => navigate('/signup')}>
                                Start free
                            </Button>
                        </div>
                        <div className="h-4 w-px bg-on-surface/10 hidden sm:block" />
                        <ModeToggle />
                    </div>
                </div>
            </header>

            <main className="flex-1 flex flex-col">
                {/* ── Hero ────────────────────────────── */}
                <section className="relative min-h-[90vh] flex flex-col items-center justify-center text-center px-6 py-28 lg:py-36 overflow-hidden">
                    <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-primary/20 to-transparent" />
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[1200px] h-[800px] bg-primary/[0.03] rounded-full blur-[140px] pointer-events-none" />
                    
                    <div className="max-w-5xl space-y-12 animate-in fade-in slide-in-from-bottom-8 duration-1000 relative z-10">
                        <div className="flex justify-center">
                            <Badge className="rounded-full border-primary/20 bg-primary/5 text-primary px-5 py-1.5 text-xs font-semibold shadow-inner gap-2">
                                <Activity className="w-3 h-3 animate-pulse" /> Open-source identity platform — now generally available
                            </Badge>
                        </div>

                        <h1 className="text-5xl sm:text-7xl lg:text-8xl font-bold tracking-tight text-on-surface leading-[0.9] italic">
                            Trusted identity<br />
                            for the <span className="text-primary italic">modern stack</span>
                        </h1>

                        <p className="text-xl text-on-surface-variant/60 font-medium leading-relaxed max-w-2xl mx-auto">
                            Enterprise-grade authentication, authorization, and user management — self-hosted or cloud. SOC 2 ready, OIDC native, open core.
                        </p>

                        <div className="flex flex-col sm:flex-row items-center justify-center gap-6">
                            <Button className="px-12 h-16 text-sm font-bold tracking-tight rounded-2xl shadow-2xl shadow-primary/30 hover:shadow-primary/50 transition-all hover:scale-105 active:scale-95 group" onClick={() => navigate('/signup?plan=free')}>
                                Get started free <ArrowRight className="ml-3 w-5 h-5 group-hover:translate-x-1 transition-transform" />
                            </Button>
                            <Button variant="outline" className="px-12 h-16 text-sm font-semibold tracking-tight rounded-2xl border-2 border-on-surface/10 hover:bg-card transition-all hover:shadow-xl hover:shadow-on-surface/5 gap-3"
                                onClick={() => window.open('https://github.com/dhawalhost/wardseal', '_blank')}>
                                <Github className="w-5 h-5" /> View on GitHub
                            </Button>
                        </div>

                        {/* Trust bar */}
                        <div className="pt-16 grid grid-cols-2 lg:grid-cols-4 gap-12 max-w-4xl mx-auto">
                            {[
                                { icon: <ShieldCheck className="w-5 h-5" />, text: 'SOC 2 ready', label: 'Compliance' },
                                { icon: <Globe className="w-5 h-5" />, text: 'OIDC & SAML', label: 'Protocols' },
                                { icon: <Server className="w-5 h-5" />, text: 'Kubernetes native', label: 'Deployment' },
                                { icon: <Terminal className="w-5 h-5" />, text: 'MIT licensed', label: 'Open source' },
                            ].map(({ icon, text, label }) => (
                                <div key={text} className="flex flex-col items-center gap-2 group cursor-default">
                                    <div className="text-on-surface-variant/20 group-hover:text-primary transition-colors duration-500">{icon}</div>
                                    <p className="text-sm font-bold tracking-tight text-on-surface leading-none">{text}</p>
                                    <p className="text-[11px] font-medium text-on-surface-variant/40 italic">{label}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                </section>

                {/* ── Social Proof Numbers ─────────────────── */}
                <section className="py-20 px-10 border-y border-on-surface/5 bg-card relative overflow-hidden group">
                    <div className="absolute inset-0 bg-primary/[0.01] opacity-0 group-hover:opacity-100 transition-opacity duration-1000" />
                    <div className="max-w-7xl mx-auto grid grid-cols-2 lg:grid-cols-4 gap-12 text-center items-center">
                        {[
                            { value: '12.4K', label: 'Developers trust us', sub: 'Active users' },
                            { value: '99.99%', label: 'Uptime SLA', sub: 'Guaranteed availability' },
                            { value: '<24ms', label: 'Auth latency', sub: 'Global average' },
                            { value: '4.2PB', label: 'Identity events processed', sub: 'Cumulative' },
                        ].map(({ value, label, sub }) => (
                            <div key={label} className="space-y-2 relative">
                                <p className="text-5xl font-black tracking-tighter text-on-surface italic">{value}</p>
                                <div className="space-y-1">
                                    <p className="text-[11px] font-bold text-primary italic leading-none">{label}</p>
                                    <p className="text-[10px] font-medium text-on-surface-variant/40">{sub}</p>
                                </div>
                            </div>
                        ))}
                    </div>
                </section>

                {/* ── Features ─────────────────────── */}
                <section id="features" className="py-32 px-10 relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-primary/[0.02] rounded-full blur-[120px] -mr-96 -mt-96" />
                    <div className="max-w-7xl mx-auto">
                        <div className="flex flex-col md:flex-row items-end justify-between mb-24 gap-8">
                            <div className="space-y-6">
                                <p className="text-sm font-semibold text-primary">Features</p>
                                <h2 className="text-5xl lg:text-7xl font-bold tracking-tight text-on-surface leading-[0.9] italic">Security by design</h2>
                                <p className="text-on-surface-variant/50 font-medium text-lg max-w-xl leading-relaxed">One unified platform to manage users, machine identities, and compliance governance.</p>
                            </div>
                            <Button size="lg" variant="outline" className="rounded-2xl h-14 px-10 border-2 font-semibold text-sm border-on-surface/10 hover:border-primary transition-all group">
                                Explore the API <Activity className="ml-3 w-4 h-4 text-primary group-hover:animate-pulse" />
                            </Button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                            <FeatureCard 
                                category="Authentication"
                                icon={<ShieldCheck className="w-8 h-8" />} 
                                title="Enterprise SSO"
                                description="OIDC & SAML 2.0 federation out of the box. Support for multi-tenancy, isolated namespaces, and granular access policies." />
                            <FeatureCard 
                                category="Security"
                                icon={<Fingerprint className="w-8 h-8" />} 
                                title="Adaptive MFA"
                                description="Context-aware WebAuthn passkeys, TOTP, and biometric authentication. Risk-based step-up for sensitive operations." />
                            <FeatureCard 
                                category="Directory"
                                icon={<Database className="w-8 h-8" />} 
                                title="SCIM provisioning"
                                description="Automated user lifecycle management via SCIM 2.0. Sync and provision identities from Okta, Microsoft Entra, or your own HR system." />
                            <FeatureCard 
                                category="Compliance"
                                icon={<Activity className="w-8 h-8" />} 
                                title="Audit logs"
                                description="Tamper-evident, immutable event streams. Built-in support for SOC 2, HIPAA, and Zero Trust certification requirements." />
                            <FeatureCard 
                                category="Authorization"
                                icon={<KeyRound className="w-8 h-8" />} 
                                title="Policy engine"
                                description="Fine-grained RBAC and ABAC authorization. Define resource-level access rules as code or manage them through the admin console." />
                            <FeatureCard 
                                category="Integrations"
                                icon={<Webhook className="w-8 h-8" />} 
                                title="Webhooks & events"
                                description="Real-time event delivery to any endpoint. Trigger automations, SIEM alerts, or custom workflows on authentication events." />
                        </div>
                    </div>
                </section>

                {/* ── How it works ─────────────────── */}
                <section id="how-it-works" className="py-32 px-10 bg-card relative">
                    <div className="max-w-7xl mx-auto grid lg:grid-cols-2 gap-24 items-center">
                        <div className="space-y-12">
                            <div className="space-y-6">
                                <p className="text-sm font-semibold text-primary">How it works</p>
                                <h2 className="text-5xl lg:text-7xl font-bold tracking-tight text-on-surface leading-[0.9] italic">Up in minutes</h2>
                                <p className="text-on-surface-variant/50 font-medium text-lg leading-relaxed">From zero to a production-ready identity layer in minutes, not days.</p>
                            </div>
                            
                            <div className="space-y-12">
                                <StepCard step="01" title="Create your tenant"
                                    description="Provision your organization. Your namespace is automatically isolated with secure, privacy-first defaults." />
                                <StepCard step="02" title="Connect your apps"
                                    description="Register your applications and grab OAuth 2.0 credentials. Point your SDK at the WardSeal issuer endpoint." />
                                <StepCard step="03" title="Enable SSO and MFA"
                                    description="Activate Single Sign-On and adaptive multi-factor authentication. Manage authentication flows at any scale." />
                            </div>
                        </div>
                        
                        <GlassCard className="border-none bg-inverse overflow-hidden shadow-2xl relative shadow-primary/20">
                            <div className="absolute top-0 right-0 p-8">
                                <div className="flex gap-2">
                                    <div className="w-3 h-3 rounded-full bg-destructive/100/50" />
                                    <div className="w-3 h-3 rounded-full bg-yellow-500/50" />
                                    <div className="w-3 h-3 rounded-full bg-green-500/50" />
                                </div>
                            </div>
                            <div className="p-10 font-mono text-[13px] leading-relaxed text-on-inverse/40">
                                <div className="flex items-center gap-3 mb-6 border-b border-on-inverse/5 pb-4">
                                    <Terminal className="w-4 h-4 text-primary" />
                                    <span className="text-[10px] font-bold tracking-widest text-on-inverse/20">wardseal — helm setup</span>
                                </div>
                                <p className="text-on-inverse/40 mb-2"># Deploy to your Kubernetes cluster</p>
                                <p><span className="text-primary font-black">helm</span> install wardseal wardseal-hub/wardseal \</p>
                                <p className="pl-6">--set cluster.domain=auth.yourcompany.com \</p>
                                <p className="pl-6">--set feature.sso=true</p>
                                <br />
                                <p className="text-on-inverse/40 mb-2"># Set environment variables</p>
                                <p><span className="text-primary font-black">export</span> WS_ISSUER=https://auth.yourcompany.com</p>
                                <p><span className="text-primary font-black">export</span> WS_CLIENT_ID=your_client_id</p>
                                <br />
                                <div className="space-y-1 mt-6 animate-in fade-in duration-1000 delay-500">
                                    <p className="text-emerald-400 font-bold flex items-center gap-3">
                                        <Check className="w-4 h-4" /> 
                                        Tenant provisioned successfully
                                    </p>
                                    <p className="text-emerald-400 font-bold flex items-center gap-3">
                                        <Check className="w-4 h-4" /> 
                                        OIDC and OAuth 2.0 endpoints active
                                    </p>
                                    <p className="text-on-inverse/20 font-bold flex items-center gap-3">
                                        <Activity className="w-4 h-4 text-primary animate-pulse" /> 
                                        Waiting for first login…
                                    </p>
                                </div>
                            </div>
                            <div className="p-6 bg-card/5 border-t border-on-inverse/5 flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <Cpu className="w-4 h-4 text-primary" />
                                    <span className="text-[10px] font-bold tracking-widest text-on-inverse/30">p99 latency: 4ms</span>
                                </div>
                                <span className="text-[10px] font-bold tracking-widest text-emerald-400/50">Node healthy</span>
                            </div>
                        </GlassCard>
                    </div>
                </section>

                {/* ── Testimonials ─────────────────── */}
                <section className="py-32 px-10 bg-background border-t border-on-surface/5">
                    <div className="max-w-7xl mx-auto">
                        <div className="text-center mb-24 space-y-4">
                            <p className="text-sm font-semibold text-primary">Customer stories</p>
                            <h2 className="text-5xl lg:text-7xl font-bold tracking-tight text-on-surface leading-[0.9] italic">Trusted by teams worldwide</h2>
                        </div>
                        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-10">
                            <TestimonialCard
                                quote="The SCIM provisioning engine cut our identity lifecycle latency from hours to milliseconds. Incredibly solid architecture."
                                name="Priya S." title="Director of Security, DataMesh" avatar="PS" />
                            <TestimonialCard
                                quote="Self-hosting on our internal Kubernetes cluster was trivial. We unified SSO across 15 legacy systems in a single sprint."
                                name="Marcus R." title="Lead Engineer, CloudCore" avatar="MR" />
                            <TestimonialCard
                                quote="First-class multi-tenancy. Every customer gets isolated namespaces and custom branding from a single deployment."
                                name="Chen W." title="Principal Security Engineer, SaaS Ventures" avatar="CW" />
                        </div>
                    </div>
                </section>

                {/* ── Pricing ──────────────────────── */}
                <section id="pricing" className="py-32 px-10 relative overflow-hidden">
                    <div className="absolute top-full left-1/2 -translate-x-1/2 -translate-y-1/2 w-[1000px] h-[500px] bg-primary/[0.02] rounded-full blur-[100px]" />
                    <div className="max-w-7xl mx-auto">
                        <div className="text-center mb-24 space-y-8">
                            <p className="text-sm font-semibold text-primary">Pricing</p>
                            <h2 className="text-5xl lg:text-7xl font-bold tracking-tight text-on-surface leading-[0.9] italic">Simple, transparent pricing</h2>
                            <p className="text-on-surface-variant/50 font-medium text-lg leading-relaxed max-w-2xl mx-auto">Built for side-projects, growing startups, and global enterprises alike.</p>

                            <div className="flex justify-center">
                                <Tabs value={billing} onValueChange={v => setBilling(v as 'monthly' | 'yearly')} className="bg-card p-1.5 rounded-2xl border border-on-surface/5 shadow-xl shadow-on-surface/5">
                                    <TabsList className="bg-transparent h-12">
                                        <TabsTrigger value="monthly" className="rounded-xl px-10 text-sm font-semibold data-[state=active]:bg-primary data-[state=active]:text-white transition-all">Monthly</TabsTrigger>
                                        <TabsTrigger value="yearly" className="rounded-xl px-10 text-sm font-semibold data-[state=active]:bg-primary data-[state=active]:text-white transition-all">
                                            Annual <Badge className="ml-3 bg-success text-success-foreground rounded-lg border-none text-[10px] font-bold">Save 20%</Badge>
                                        </TabsTrigger>
                                    </TabsList>
                                </Tabs>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-10 items-stretch">
                            {/* ── Free ── */}
                            <GlassCard className="border-none bg-card p-12 transition-transform hover:scale-[1.02] duration-500 flex flex-col shadow-xl shadow-on-surface/5">
                                <div className="space-y-6 flex-1">
                                    <div className="space-y-1">
                                        <p className="text-[11px] font-semibold text-on-surface-variant/40 italic leading-none">Starter</p>
                                        <h3 className="text-3xl font-bold tracking-tight">Community</h3>
                                    </div>
                                    <div className="flex items-baseline gap-2">
                                        <span className="text-6xl font-black italic tracking-tight text-on-surface">$0</span>
                                        <span className="text-sm font-medium text-on-surface-variant/40">/ month</span>
                                    </div>
                                    <ul className="space-y-5 pt-4 mb-12">
                                        {[
                                            '500 monthly active users',
                                            '3 applications',
                                            'Social login (OIDC)',
                                            'TOTP multi-factor auth',
                                            '7-day audit history',
                                            'Community support',
                                        ].map(f => (
                                            <li key={f} className="flex items-center gap-4 group">
                                                <div className="p-1 rounded-full bg-success-subtle text-success group-hover:bg-success group-hover:text-white transition-colors flex-shrink-0">
                                                    <Check className="w-3 h-3" />
                                                </div>
                                                <span className="text-sm font-medium text-on-surface-variant/70">{f}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                                <Button variant="outline" className="w-full h-14 rounded-2xl font-semibold text-sm border-2 hover:bg-on-surface hover:text-white transition-all mt-auto" onClick={() => navigate('/signup?plan=free')}>
                                    Get started free
                                </Button>
                            </GlassCard>

                            {/* ── Pro ── */}
                            <GlassCard className="border-none bg-inverse p-12 transition-transform hover:scale-[1.05] duration-500 flex flex-col shadow-2xl shadow-primary/20 relative overflow-hidden ring-4 ring-primary/20">
                                <div className="absolute top-0 right-0 p-6">
                                    <Badge className="bg-primary text-primary-foreground border-none rounded-xl text-[10px] font-bold tracking-wide px-4 py-2 italic shadow-xl shadow-primary/40">Most popular</Badge>
                                </div>
                                <div className="space-y-6 flex-1 text-on-inverse">
                                    <div className="space-y-1">
                                        <p className="text-[11px] font-semibold text-on-inverse/30 italic leading-none">For growing teams</p>
                                        <h3 className="text-3xl font-bold tracking-tight text-primary-foreground">Professional</h3>
                                    </div>
                                    <div className="flex items-baseline gap-2">
                                        <span className="text-6xl font-black italic tracking-tight text-on-inverse">${proPrice}</span>
                                        <span className="text-sm font-medium text-on-inverse/30">/ month</span>
                                    </div>
                                    <ul className="space-y-5 pt-4 mb-12">
                                        {[
                                            '10,000 monthly active users',
                                            'Unlimited applications',
                                            'SCIM 2.0 user sync',
                                            'Passkeys (passwordless)',
                                            '90-day audit history',
                                            'Priority support',
                                        ].map(f => (
                                            <li key={f} className="flex items-center gap-4 group">
                                                <div className="p-1 rounded-full bg-primary/20 text-primary-foreground group-hover:bg-primary group-hover:text-primary-foreground transition-colors flex-shrink-0">
                                                    <Check className="w-3 h-3" />
                                                </div>
                                                <span className="text-sm font-medium text-on-inverse/60">{f}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                                <Button className="w-full h-14 rounded-2xl font-semibold text-sm shadow-xl shadow-primary/40 transition-all hover:scale-[1.02] mt-auto" onClick={() => navigate('/signup?plan=pro')}>
                                    Start for ${proPrice}/mo
                                </Button>
                            </GlassCard>

                            {/* ── Enterprise ── */}
                            <GlassCard className="border-none bg-card p-12 transition-transform hover:scale-[1.02] duration-500 flex flex-col shadow-xl shadow-on-surface/5">
                                <div className="space-y-6 flex-1">
                                    <div className="space-y-1">
                                        <p className="text-[11px] font-semibold text-on-surface-variant/40 italic leading-none">For enterprises</p>
                                        <h3 className="text-3xl font-bold tracking-tight">Enterprise</h3>
                                    </div>
                                    <div className="flex items-baseline gap-2">
                                        <span className="text-6xl font-black italic tracking-tight text-on-surface">${teamPrice}</span>
                                        <span className="text-sm font-medium text-on-surface-variant/40">/ month</span>
                                    </div>
                                    <ul className="space-y-5 pt-4 mb-12">
                                        {[
                                            '100,000 monthly active users',
                                            'Multi-tenant namespaces',
                                            'SAML 2.0 federation',
                                            'Compliance & governance tools',
                                            '365-day audit retention',
                                            'Dedicated support & SLA',
                                        ].map(f => (
                                            <li key={f} className="flex items-center gap-4 group">
                                                <div className="p-1 rounded-full bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors flex-shrink-0">
                                                    <Check className="w-3 h-3" />
                                                </div>
                                                <span className="text-sm font-medium text-on-surface-variant/70">{f}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                                <Button variant="outline" className="w-full h-14 rounded-2xl font-semibold text-sm border-2 hover:bg-on-surface hover:text-white transition-all mt-auto" onClick={() => navigate('/signup?plan=team')}>
                                    Contact sales
                                </Button>
                            </GlassCard>
                        </div>
                    </div>
                </section>

                {/* ── FAQ ──────────────────────────── */}
                <section className="py-32 px-10 bg-card border-t border-on-surface/5">
                    <div className="max-w-4xl mx-auto grid lg:grid-cols-5 gap-24">
                        <div className="lg:col-span-2 space-y-8">
                            <div className="space-y-4">
                                <p className="text-sm font-semibold text-primary">FAQ</p>
                                <h2 className="text-5xl lg:text-7xl font-bold tracking-tight text-on-surface leading-[0.9] italic">Questions</h2>
                            </div>
                            <div className="p-8 rounded-3xl bg-background space-y-4 border border-on-surface/5 shadow-inner">
                                <h4 className="text-sm font-bold text-on-surface leading-relaxed">Still have questions?</h4>
                                <p className="text-sm text-on-surface-variant/60">Our team is happy to help you find the right setup for your use case.</p>
                                <Button variant="link" className="p-0 h-auto text-primary font-semibold text-sm hover:opacity-70 transition-opacity gap-2">
                                    Contact support <ArrowRight className="w-4 h-4" />
                                </Button>
                            </div>
                        </div>
                        <div className="lg:col-span-3">
                            {[
                                {
                                    q: 'Can I self-host WardSeal?',
                                    a: 'Yes — WardSeal is fully open source under the MIT license. Deploy to any Kubernetes cluster, bare metal server, or private cloud using our official Helm charts.',
                                },
                                {
                                    q: 'How are monthly active users counted?',
                                    a: 'A monthly active user (MAU) is any unique end-user who performs an authentication in a given calendar month. Admin accounts and service accounts are not counted.',
                                },
                                {
                                    q: 'Which identity providers do you support?',
                                    a: 'We support Okta, Microsoft Entra ID, Google Workspace, Ping Identity, and Auth0 via standard OIDC or SAML 2.0 — no custom connectors needed.',
                                },
                                {
                                    q: 'Is WardSeal compliant with SOC 2 and HIPAA?',
                                    a: 'WardSeal ships with tamper-evident audit logs, immutable event streams, adaptive MFA, and role-based access controls that map to SOC 2 Type II and HIPAA requirements.',
                                },
                            ].map(({ q, a }) => <FaqItem key={q} question={q} answer={a} />)}
                        </div>
                    </div>
                </section>

                {/* ── CTA ──────────────────────────── */}
                <section className="py-40 px-10 relative overflow-hidden group">
                    <div className="absolute inset-0 bg-primary/[0.02] flex items-center justify-center">
                        <div className="w-[1400px] h-[600px] bg-primary/[0.03] rounded-full blur-[140px] group-hover:scale-110 transition-transform duration-1000" />
                    </div>
                    <div className="max-w-4xl mx-auto space-y-12 text-center relative z-10">
                        <h2 className="text-6xl lg:text-[120px] font-bold tracking-tight text-on-surface leading-[0.8] italic">Start for free</h2>
                        <p className="text-xl lg:text-2xl text-on-surface-variant/40 font-medium tracking-tight">No credit card required. Production-ready in minutes.</p>
                        <div className="flex flex-col sm:flex-row items-center justify-center gap-6 pt-4">
                            <Button className="px-16 h-20 text-base font-bold tracking-tight rounded-3xl shadow-2xl shadow-primary/40 hover:shadow-primary/60 transition-all hover:scale-105 active:scale-95 group" onClick={() => navigate('/signup')}>
                                Create a free account <ArrowRight className="ml-4 w-6 h-6 group-hover:translate-x-2 transition-transform" />
                            </Button>
                            <Button variant="ghost" className="h-20 px-10 text-sm font-semibold gap-3" onClick={() => window.open('https://github.com/dhawalhost/wardseal', '_blank')}>
                                <Github className="w-5 h-5" /> View the source
                            </Button>
                        </div>
                    </div>
                </section>
            </main>

            {/* ── Footer ──────────────────────────── */}
            <footer className="py-24 px-10 border-t border-on-surface/5 bg-card">
                <div className="max-w-7xl mx-auto grid grid-cols-2 lg:grid-cols-5 gap-16">
                    <div className="lg:col-span-2 space-y-8">
                        {/* Footer logo */}
                        <div className="flex items-center gap-3">
                            <div className="w-9 h-9 flex items-center justify-center bg-primary rounded-[14px] shadow-md shadow-primary/20">
                                <ShieldCheck className="w-5 h-5 text-white" />
                            </div>
                            <span className="font-bold text-xl tracking-tight text-on-surface">WardSeal</span>
                        </div>
                        <p className="text-sm font-medium text-on-surface-variant/50 max-w-xs leading-relaxed">
                            Open-source Identity & Access Management for the modern enterprise. SOC 2 ready, OIDC native, MIT licensed.
                        </p>
                        <div className="flex gap-5">
                            <a href="https://github.com/dhawalhost/wardseal" target="_blank" rel="noreferrer" className="text-on-surface-variant/40 hover:text-primary transition-colors" aria-label="GitHub">
                                <Github className="w-5 h-5" />
                            </a>
                            <a href="https://twitter.com/wardseal" target="_blank" rel="noreferrer" className="text-on-surface-variant/40 hover:text-primary transition-colors" aria-label="Twitter">
                                <Twitter className="w-5 h-5" />
                            </a>
                            <a href="mailto:hello@wardseal.com" className="text-on-surface-variant/40 hover:text-primary transition-colors" aria-label="Email">
                                <Mail className="w-5 h-5" />
                            </a>
                        </div>
                    </div>
                    <div>
                        <h4 className="text-sm font-bold text-on-surface mb-6">Product</h4>
                        <ul className="space-y-4 text-sm font-medium text-on-surface-variant/50">
                            <li><a href="#features" className="hover:text-primary transition-colors">Features</a></li>
                            <li><a href="#pricing" className="hover:text-primary transition-colors">Pricing</a></li>
                            <li><a href="#" className="hover:text-primary transition-colors">Changelog</a></li>
                            <li><a href="#" className="hover:text-primary transition-colors">Roadmap</a></li>
                        </ul>
                    </div>
                    <div>
                        <h4 className="text-sm font-bold text-on-surface mb-6">Developers</h4>
                        <ul className="space-y-4 text-sm font-medium text-on-surface-variant/50">
                            <li><a href="#" className="hover:text-primary transition-colors">Documentation</a></li>
                            <li><a href="#" className="hover:text-primary transition-colors">API reference</a></li>
                            <li><a href="https://github.com/dhawalhost/wardseal" target="_blank" rel="noreferrer" className="hover:text-primary transition-colors">GitHub</a></li>
                            <li><a href="#" className="hover:text-primary transition-colors">Status page</a></li>
                        </ul>
                    </div>
                    <div>
                        <h4 className="text-sm font-bold text-on-surface mb-6">Company</h4>
                        <ul className="space-y-4 text-sm font-medium text-on-surface-variant/50">
                            <li><a href="#" className="hover:text-primary transition-colors">About</a></li>
                            <li><a href="mailto:sales@wardseal.com" className="hover:text-primary transition-colors">Contact sales</a></li>
                            <li><a href="#" className="hover:text-primary transition-colors">Privacy policy</a></li>
                            <li><a href="#" className="hover:text-primary transition-colors">Terms of service</a></li>
                        </ul>
                    </div>
                </div>
                <div className="max-w-7xl mx-auto mt-20 pt-10 border-t border-on-surface/5 flex flex-col lg:flex-row justify-between gap-6 text-sm font-medium text-on-surface-variant/40">
                    <p>&copy; {new Date().getFullYear()} WardSeal. All rights reserved.</p>
                    <p>Built on open standards — OIDC · SAML · SCIM · WebAuthn</p>
                </div>
            </footer>
        </div>
    );
};

export default Landing;
