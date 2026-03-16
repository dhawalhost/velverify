import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
    ArrowRight, ShieldCheck, Lock, Globe, Zap, Server, Code, Check, X,
    Users, KeyRound, Fingerprint, BarChart3, Webhook, Building2,
    ChevronDown, ChevronUp, Star, ExternalLink, Github, Mail, Twitter,
    PlayCircle,
} from 'lucide-react';
import { ModeToggle } from '@/components/mode-toggle';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';

// ──────────────────────────────────────
// Sub-components
// ──────────────────────────────────────

const FeatureCard = ({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) => (
    <div className="p-6 rounded-2xl bg-card border border-border/50 shadow-sm hover:shadow-lg hover:border-primary/30 transition-all duration-300 group">
        <div className="mb-4 p-3 bg-primary/5 rounded-xl w-fit group-hover:bg-primary/10 transition-colors">{icon}</div>
        <h3 className="text-lg font-semibold mb-2">{title}</h3>
        <p className="text-muted-foreground text-sm leading-relaxed">{description}</p>
    </div>
);

const StepCard = ({ step, title, description }: { step: string; title: string; description: string }) => (
    <div className="flex gap-5">
        <div className="flex-shrink-0 w-10 h-10 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center text-primary font-bold text-sm">{step}</div>
        <div>
            <h3 className="font-semibold mb-1">{title}</h3>
            <p className="text-muted-foreground text-sm leading-relaxed">{description}</p>
        </div>
    </div>
);

const FaqItem = ({ question, answer }: { question: string; answer: string }) => {
    const [open, setOpen] = useState(false);
    return (
        <div className="border-b border-border/60 last:border-0">
            <button className="w-full flex items-center justify-between py-5 text-left text-sm font-medium hover:text-primary transition-colors gap-4" onClick={() => setOpen(o => !o)}>
                <span>{question}</span>
                {open ? <ChevronUp className="w-4 h-4 flex-shrink-0 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 flex-shrink-0 text-muted-foreground" />}
            </button>
            {open && <p className="pb-5 text-sm text-muted-foreground leading-relaxed">{answer}</p>}
        </div>
    );
};

const TestimonialCard = ({ quote, name, title, avatar }: { quote: string; name: string; title: string; avatar: string }) => (
    <Card className="border-border/50 bg-card/60 backdrop-blur-sm">
        <CardContent className="pt-6 pb-5 space-y-4">
            <div className="flex gap-1">{Array.from({ length: 5 }).map((_, i) => <Star key={i} className="w-4 h-4 fill-yellow-400 text-yellow-400" />)}</div>
            <p className="text-sm text-muted-foreground leading-relaxed">"{quote}"</p>
            <div className="flex items-center gap-3 pt-1">
                <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary font-bold text-sm">{avatar}</div>
                <div>
                    <p className="text-sm font-medium">{name}</p>
                    <p className="text-xs text-muted-foreground">{title}</p>
                </div>
            </div>
        </CardContent>
    </Card>
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
        <div className="min-h-screen bg-background text-foreground flex flex-col font-sans">
            {/* ── Header ──────────────────────────── */}
            <header className="px-6 py-4 flex items-center justify-between border-b border-border/40 backdrop-blur-md sticky top-0 z-50 bg-background/80">
                <a href="/" className="flex items-center gap-2">
                    <div className="w-8 h-8 flex items-center justify-center bg-primary/20 rounded-lg">
                        <img src="/wardseal.svg" alt="WardSeal" className="w-6 h-6 object-contain" />
                    </div>
                    <span className="font-bold text-xl tracking-tight">WardSeal</span>
                </a>
                <div className="flex items-center gap-4">
                    <nav className="hidden md:flex gap-6 text-sm font-medium text-muted-foreground mr-4">
                        <a href="#features" className="hover:text-foreground transition-colors">Features</a>
                        <a href="#how-it-works" className="hover:text-foreground transition-colors">How it works</a>
                        <a href="#pricing" className="hover:text-foreground transition-colors">Pricing</a>
                        <a href="https://github.com/dhawalhost/wardseal" target="_blank" rel="noreferrer" className="hover:text-foreground transition-colors">Docs</a>
                    </nav>
                    <ModeToggle />
                    <Button variant="ghost" size="sm" onClick={() => navigate('/login')}>Sign In</Button>
                    <Button size="sm" onClick={() => navigate('/signup')}>Get Started</Button>
                </div>
            </header>

            {/* ── Hero ────────────────────────────── */}
            <main className="flex-1 flex flex-col">
                <section className="relative flex-1 flex flex-col items-center justify-center text-center px-4 py-28 lg:py-36 overflow-hidden">
                    <div className="absolute -top-32 -left-24 w-[500px] h-[500px] bg-primary/15 rounded-full blur-3xl opacity-60 animate-pulse" />
                    <div className="absolute bottom-0 right-0 w-[400px] h-[400px] bg-blue-600/15 rounded-full blur-3xl opacity-60 animate-pulse delay-1000" />

                    <div className="max-w-4xl space-y-7 animate-in fade-in slide-in-from-bottom-6 duration-700 relative z-10">
                        <Badge variant="outline" className="rounded-full border-primary/30 bg-primary/5 text-primary px-4 py-1 text-sm">
                            <Zap className="w-3.5 h-3.5 mr-1.5 fill-current" /> v1.0 — Enterprise Ready
                        </Badge>

                        <h1 className="text-5xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-foreground leading-tight">
                            Identity Infrastructure<br />
                            for the{' '}
                            <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary via-blue-500 to-purple-600">
                                Modern Cloud
                            </span>
                        </h1>

                        <p className="text-xl sm:text-2xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
                            Open-source IAM that ships Single Sign-On, Adaptive MFA,<br className="hidden sm:block" />
                            and Zero Trust access control in under 10 minutes.
                        </p>

                        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-6">
                            <Button size="lg" className="px-8 h-13 text-base rounded-full shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow" onClick={() => navigate('/signup?plan=free')}>
                                Start for Free <ArrowRight className="ml-2 w-4 h-4" />
                            </Button>
                            <Button size="lg" variant="outline" className="px-8 h-13 text-base rounded-full border-primary/20 hover:bg-primary/5 gap-2"
                                onClick={() => window.open('https://github.com/dhawalhost/wardseal', '_blank')}>
                                <Github className="w-4 h-4" /> Star on GitHub
                            </Button>
                            <Button size="lg" variant="ghost" className="px-8 h-13 text-base rounded-full gap-2" onClick={() => navigate('/login')}>
                                <PlayCircle className="w-4 h-4" /> View Demo
                            </Button>
                        </div>

                        {/* Trust bar */}
                        <div className="pt-10 flex flex-wrap justify-center gap-8 text-sm text-muted-foreground">
                            {[
                                { icon: <ShieldCheck className="w-4 h-4" />, text: 'SOC 2 Ready' },
                                { icon: <Globe className="w-4 h-4" />, text: 'OIDC & SAML 2.0' },
                                { icon: <Server className="w-4 h-4" />, text: 'Self-host or Cloud' },
                                { icon: <Code className="w-4 h-4" />, text: 'Open Source (MIT)' },
                            ].map(({ icon, text }) => (
                                <div key={text} className="flex items-center gap-1.5 opacity-70 hover:opacity-100 transition-opacity">
                                    {icon} {text}
                                </div>
                            ))}
                        </div>
                    </div>
                </section>

                {/* ── Social Proof ─────────────────── */}
                <section className="py-10 px-6 border-y border-border/40 bg-muted/20">
                    <div className="max-w-5xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
                        {[
                            { value: '10k+', label: 'Developers' },
                            { value: '500+', label: 'Companies' },
                            { value: '99.99%', label: 'Uptime SLA' },
                            { value: '<50ms', label: 'Auth latency' },
                        ].map(({ value, label }) => (
                            <div key={label}>
                                <p className="text-3xl font-extrabold text-foreground">{value}</p>
                                <p className="text-sm text-muted-foreground mt-1">{label}</p>
                            </div>
                        ))}
                    </div>
                </section>

                {/* ── Features ─────────────────────── */}
                <section id="features" className="py-24 px-6 bg-muted/20">
                    <div className="max-w-6xl mx-auto">
                        <div className="text-center mb-14">
                            <Badge variant="outline" className="mb-4">Platform Features</Badge>
                            <h2 className="text-3xl font-bold tracking-tight mb-4">Enterprise Security, Zero Complexity</h2>
                            <p className="text-muted-foreground text-lg max-w-2xl mx-auto">One platform to manage users, machines, apps, and compliance — without stitching together five vendors.</p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            <FeatureCard icon={<ShieldCheck className="w-7 h-7 text-primary" />} title="Enterprise SSO"
                                description="OIDC & SAML 2.0 federation with any identity provider. Built-in multi-tenancy and per-org SSO policies." />
                            <FeatureCard icon={<Lock className="w-7 h-7 text-primary" />} title="Adaptive MFA"
                                description="TOTP, WebAuthn passkeys, magic links, and risk-based step-up authentication to stop account takeovers." />
                            <FeatureCard icon={<Users className="w-7 h-7 text-primary" />} title="Directory & SCIM"
                                description="Full user lifecycle management with SCIM 2.0 provisioning. Sync from Okta, Azure AD, or Workday automatically." />
                            <FeatureCard icon={<Globe className="w-7 h-7 text-primary" />} title="Identity Governance"
                                description="Automated access reviews, certification campaigns, and approval workflows to stay audit-ready year round." />
                            <FeatureCard icon={<KeyRound className="w-7 h-7 text-primary" />} title="Fine-grained RBAC"
                                description="Roles, policies, and resource-level permissions managed through a rich API or the admin console." />
                            <FeatureCard icon={<Fingerprint className="w-7 h-7 text-primary" />} title="Passwordless Auth"
                                description="Passkeys (WebAuthn), email magic links, and social login cut password friction while boosting security." />
                            <FeatureCard icon={<Webhook className="w-7 h-7 text-primary" />} title="Webhooks & Events"
                                description="Real-time event streaming to your SIEM, Slack, or custom services with retry and delivery guarantees." />
                            <FeatureCard icon={<BarChart3 className="w-7 h-7 text-primary" />} title="Audit Logs"
                                description="Tamper-evident, searchable audit trail for all authentication, authorization, and admin events." />
                            <FeatureCard icon={<Building2 className="w-7 h-7 text-primary" />} title="Multi-tenancy"
                                description="Serve thousands of customer organizations with isolated namespaces, branding, and SSO from a single deployment." />
                        </div>
                    </div>
                </section>

                {/* ── How it works ─────────────────── */}
                <section id="how-it-works" className="py-24 px-6">
                    <div className="max-w-5xl mx-auto grid md:grid-cols-2 gap-16 items-center">
                        <div>
                            <Badge variant="outline" className="mb-4">Quick Start</Badge>
                            <h2 className="text-3xl font-bold tracking-tight mb-6">Up and running in minutes</h2>
                            <div className="space-y-8">
                                <StepCard step="1" title="Create your account"
                                    description="Sign up for free. No credit card required. Your tenant is provisioned instantly with sane security defaults." />
                                <StepCard step="2" title="Connect your app"
                                    description="Register an OAuth 2.0 / OIDC application in the console. Grab the client ID and point your SDK at WardSeal's issuer URL." />
                                <StepCard step="3" title="Configure SSO & MFA"
                                    description="Enable social login, enterprise SSO, or passwordless in a few clicks. Add MFA policies with step-up for sensitive actions." />
                                <StepCard step="4" title="Go live"
                                    description="Deploy to cloud or self-host on Kubernetes. Use our Helm chart or Docker Compose for a production-ready stack in under an hour." />
                            </div>
                        </div>
                        <div className="hidden md:block rounded-2xl border border-border/50 bg-muted/30 p-6 font-mono text-xs leading-6 shadow-inner overflow-x-auto">
                            <p className="text-muted-foreground mb-2"># Install via Helm</p>
                            <p><span className="text-primary">helm</span> repo add wardseal https://charts.wardseal.com</p>
                            <p><span className="text-primary">helm</span> install wardseal wardseal/wardseal \</p>
                            <p>{'  '}--set auth.domain=auth.example.com \</p>
                            <p>{'  '}--set global.mode=cloud</p>
                            <br />
                            <p className="text-muted-foreground"># OIDC discovery</p>
                            <p><span className="text-primary">curl</span> https://auth.example.com/t/acme/</p>
                            <p>{'  '}.well-known/openid-configuration</p>
                            <br />
                            <p className="text-green-500">✓ Issuer: https://auth.example.com/t/acme</p>
                            <p className="text-green-500">✓ JWKS, token, userinfo endpoints live</p>
                            <p className="text-green-500">✓ MFA policies active</p>
                        </div>
                    </div>
                </section>

                {/* ── Testimonials ─────────────────── */}
                <section className="py-24 px-6 bg-muted/20 border-t border-border/40">
                    <div className="max-w-5xl mx-auto">
                        <div className="text-center mb-12">
                            <Badge variant="outline" className="mb-4">Testimonials</Badge>
                            <h2 className="text-3xl font-bold tracking-tight">Trusted by engineering teams</h2>
                        </div>
                        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
                            <TestimonialCard
                                quote="WardSeal's SCIM provisioning cut our onboarding time from hours to minutes. The audit trail alone saved us two compliance audits."
                                name="Priya S." title="Head of Platform, FinStack" avatar="PS" />
                            <TestimonialCard
                                quote="Self-hosting on k8s was trivial. We had SSO working with our existing Azure AD tenant in under 30 minutes using the Helm chart."
                                name="Marcus R." title="CTO, Datawave" avatar="MR" />
                            <TestimonialCard
                                quote="The multi-tenant support is first-class. Each of our customers gets an isolated identity namespace and custom SSO — no extra infra."
                                name="Chen W." title="Engineering Manager, SaaSly" avatar="CW" />
                        </div>
                    </div>
                </section>

                {/* ── Pricing ──────────────────────── */}
                <section id="pricing" className="py-24 px-6">
                    <div className="max-w-6xl mx-auto">
                        <div className="text-center mb-12">
                            <Badge variant="outline" className="mb-4">Pricing</Badge>
                            <h2 className="text-3xl font-bold tracking-tight mb-3">Simple, transparent pricing</h2>
                            <p className="text-muted-foreground text-lg">Start free. Upgrade when you're ready. Cancel anytime.</p>

                            {/* Billing toggle */}
                            <div className="mt-6 flex justify-center">
                                <Tabs value={billing} onValueChange={v => setBilling(v as 'monthly' | 'yearly')}>
                                    <TabsList className="rounded-full">
                                        <TabsTrigger value="monthly" className="rounded-full">Monthly</TabsTrigger>
                                        <TabsTrigger value="yearly" className="rounded-full">
                                            Yearly <Badge className="ml-2 bg-green-500/15 text-green-600 border-green-500/20 text-xs">Save 20%</Badge>
                                        </TabsTrigger>
                                    </TabsList>
                                </Tabs>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 items-start">
                            {/* ── Free ── */}
                            <Card className="border-border/50">
                                <CardHeader>
                                    <CardTitle>Free</CardTitle>
                                    <CardDescription>For individuals & side-projects.</CardDescription>
                                    <div className="mt-4 flex items-end gap-1">
                                        <span className="text-4xl font-extrabold">$0</span>
                                        <span className="text-muted-foreground pb-1">/mo</span>
                                    </div>
                                </CardHeader>
                                <CardContent>
                                    <ul className="space-y-2.5 text-sm">
                                        {[
                                            '500 monthly active users',
                                            '3 applications',
                                            'Social login (Google, GitHub)',
                                            'Email / password auth',
                                            'TOTP MFA',
                                            'Community support',
                                            '7-day audit log retention',
                                        ].map(f => (
                                            <li key={f} className="flex items-start gap-2">
                                                <Check className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                                                <span>{f}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </CardContent>
                                <CardFooter>
                                    <Button variant="outline" className="w-full" onClick={() => navigate('/signup?plan=free')}>
                                        Get started free
                                    </Button>
                                </CardFooter>
                            </Card>

                            {/* ── Pro (highlighted) ── */}
                            <Card className="border-primary/50 shadow-xl shadow-primary/10 relative overflow-hidden">
                                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-primary via-blue-500 to-purple-600" />
                                <CardHeader>
                                    <div className="flex items-center justify-between">
                                        <CardTitle>Pro</CardTitle>
                                        <Badge className="bg-primary/10 text-primary border-primary/20">Most popular</Badge>
                                    </div>
                                    <CardDescription>For growing SaaS and small teams.</CardDescription>
                                    <div className="mt-4 flex items-end gap-1">
                                        <span className="text-4xl font-extrabold">${proPrice}</span>
                                        <span className="text-muted-foreground pb-1">/mo</span>
                                    </div>
                                    {billing === 'yearly' && <p className="text-xs text-green-600 mt-1">Billed as ${proPrice * 12}/yr — save ${(29 - proPrice) * 12}</p>}
                                </CardHeader>
                                <CardContent>
                                    <ul className="space-y-2.5 text-sm">
                                        {[
                                            'Everything in Free',
                                            '10,000 monthly active users',
                                            'Unlimited applications',
                                            'OIDC & OAuth 2.0 federation',
                                            'Magic links & Passkeys',
                                            'SCIM 2.0 provisioning',
                                            'Webhooks & event streams',
                                            '90-day audit log retention',
                                            'Email support (48 h SLA)',
                                        ].map(f => (
                                            <li key={f} className="flex items-start gap-2">
                                                <Check className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                                                <span>{f}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </CardContent>
                                <CardFooter>
                                    <Button className="w-full shadow-md shadow-primary/20" onClick={() => navigate('/signup?plan=pro')}>
                                        Start Pro trial <ArrowRight className="ml-2 w-4 h-4" />
                                    </Button>
                                </CardFooter>
                            </Card>

                            {/* ── Team ── */}
                            <Card className="border-border/50 bg-muted/10">
                                <CardHeader>
                                    <CardTitle>Team</CardTitle>
                                    <CardDescription>For larger teams & multi-tenant platforms.</CardDescription>
                                    <div className="mt-4 flex items-end gap-1">
                                        <span className="text-4xl font-extrabold">${teamPrice}</span>
                                        <span className="text-muted-foreground pb-1">/mo</span>
                                    </div>
                                    {billing === 'yearly' && <p className="text-xs text-green-600 mt-1">Billed as ${teamPrice * 12}/yr — save ${(99 - teamPrice) * 12}</p>}
                                </CardHeader>
                                <CardContent>
                                    <ul className="space-y-2.5 text-sm">
                                        {[
                                            'Everything in Pro',
                                            '100,000 monthly active users',
                                            'SAML 2.0 federation',
                                            'Multi-organization (multi-tenant)',
                                            'Device trust & posture checks',
                                            'Identity governance & access reviews',
                                            'Custom branding per organization',
                                            '1-year audit log retention',
                                            'Priority support (4 h SLA)',
                                        ].map(f => (
                                            <li key={f} className="flex items-start gap-2">
                                                <Check className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                                                <span>{f}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </CardContent>
                                <CardFooter>
                                    <Button variant="outline" className="w-full" onClick={() => navigate('/signup?plan=team')}>
                                        Start Team trial
                                    </Button>
                                </CardFooter>
                            </Card>
                        </div>

                        {/* Enterprise callout */}
                        <div className="mt-10 rounded-2xl border border-border/50 bg-gradient-to-br from-primary/5 via-background to-blue-500/5 p-8 flex flex-col md:flex-row items-center justify-between gap-6">
                            <div>
                                <h3 className="text-xl font-semibold mb-1">Need an Enterprise license?</h3>
                                <p className="text-muted-foreground text-sm max-w-lg">
                                    Unlimited users, dedicated infrastructure, SOC 2 reports, custom SLAs, self-host on your private cloud, and a dedicated customer success engineer.
                                </p>
                                <ul className="mt-4 grid grid-cols-2 gap-2 text-sm">
                                    {['SSO (SAML & OIDC)', 'Air-gapped / private cloud', 'Custom data residency', 'Volume discounts', '24/7 Pager support', 'Compliance reports (SOC2, ISO)'].map(f => (
                                        <li key={f} className="flex items-center gap-1.5 text-muted-foreground">
                                            <Check className="w-3.5 h-3.5 text-primary flex-shrink-0" /> {f}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                            <Button size="lg" className="flex-shrink-0 rounded-full px-8" onClick={() => window.location.href = 'mailto:sales@wardseal.com'}>
                                <Mail className="mr-2 w-4 h-4" /> Contact Sales
                            </Button>
                        </div>

                        {/* Feature comparison table */}
                        <div className="mt-16 overflow-x-auto">
                            <table className="w-full text-sm border-collapse">
                                <thead>
                                    <tr className="border-b border-border">
                                        <th className="text-left py-3 pr-6 font-semibold text-muted-foreground w-1/2">Feature</th>
                                        {['Free', 'Pro', 'Team'].map(t => <th key={t} className="py-3 px-4 text-center font-semibold">{t}</th>)}
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border/40">
                                    {[
                                        ['Monthly Active Users', '500', '10k', '100k'],
                                        ['Applications', '3', 'Unlimited', 'Unlimited'],
                                        ['Social Login', true, true, true],
                                        ['TOTP MFA', true, true, true],
                                        ['Passkeys / WebAuthn', false, true, true],
                                        ['OIDC Federation', false, true, true],
                                        ['SAML 2.0', false, false, true],
                                        ['SCIM Provisioning', false, true, true],
                                        ['Multi-organization', false, false, true],
                                        ['Identity Governance', false, false, true],
                                        ['Audit Logs', '7 days', '90 days', '1 year'],
                                        ['Custom Branding', false, false, true],
                                        ['Support SLA', 'Community', '48 h', '4 h'],
                                    ].map(([feature, free, pro, team]) => (
                                        <tr key={feature as string} className="hover:bg-muted/30 transition-colors">
                                            <td className="py-3 pr-6 text-muted-foreground">{feature}</td>
                                            {[free, pro, team].map((val, i) => (
                                                <td key={i} className="py-3 px-4 text-center">
                                                    {val === true
                                                        ? <Check className="w-4 h-4 text-green-500 mx-auto" />
                                                        : val === false
                                                            ? <X className="w-4 h-4 text-muted-foreground/30 mx-auto" />
                                                            : <span className="font-medium">{val as string}</span>
                                                    }
                                                </td>
                                            ))}
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </section>

                {/* ── FAQ ──────────────────────────── */}
                <section className="py-24 px-6 bg-muted/20 border-t border-border/40">
                    <div className="max-w-2xl mx-auto">
                        <div className="text-center mb-12">
                            <Badge variant="outline" className="mb-4">FAQ</Badge>
                            <h2 className="text-3xl font-bold tracking-tight">Frequently asked questions</h2>
                        </div>
                        <div>
                            {[
                                {
                                    q: 'Can I self-host WardSeal?',
                                    a: 'Yes — WardSeal is fully open source (MIT). You can deploy it on any Kubernetes cluster, VM, or bare metal using our Helm chart or Docker Compose. The self-host version includes all platform features; commercial licenses are required for closed-source redistribution.',
                                },
                                {
                                    q: 'How does pricing work for MAUs?',
                                    a: 'A Monthly Active User (MAU) is any unique end-user who authenticates at least once in a calendar month. Internal admin accounts do not count toward your MAU limit. Overages are billed at $0.005 per additional MAU.',
                                },
                                {
                                    q: 'Is there a free trial for paid plans?',
                                    a: 'All paid plans include a 14-day free trial — no credit card required. After the trial you can downgrade to Free or enter billing details to continue.',
                                },
                                {
                                    q: 'What identity providers can I federate with?',
                                    a: 'WardSeal supports any standards-compliant OIDC or SAML 2.0 provider, including Okta, Azure AD / Entra ID, Google Workspace, Auth0, Ping Identity, Keycloak, and more.',
                                },
                                {
                                    q: 'Does WardSeal support multi-tenancy?',
                                    a: 'Yes. Each tenant is a fully isolated namespace with its own users, applications, SSO config, and branding. Tenants share infrastructure but are cryptographically separated at the data layer.',
                                },
                                {
                                    q: 'What compliance certifications does WardSeal support?',
                                    a: 'WardSeal\'s cloud is SOC 2 Type II compliant. Our audit logs, RBAC, and access review features are designed to support HIPAA, ISO 27001, and PCI DSS requirements. Enterprise customers receive compliance reports on request.',
                                },
                            ].map(({ q, a }) => <FaqItem key={q} question={q} answer={a} />)}
                        </div>
                    </div>
                </section>

                {/* ── CTA ──────────────────────────── */}
                <section className="py-28 px-6 bg-gradient-to-br from-primary/10 via-background to-blue-500/10 text-center border-t border-border/40">
                    <div className="max-w-3xl mx-auto space-y-6">
                        <h2 className="text-4xl font-extrabold tracking-tight">Start securing your users today</h2>
                        <p className="text-lg text-muted-foreground">Free forever for small projects. No credit card. No lock-in.</p>
                        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-2">
                            <Button size="lg" className="px-10 h-12 text-base rounded-full shadow-lg shadow-primary/20" onClick={() => navigate('/signup')}>
                                Create free account <ArrowRight className="ml-2 w-4 h-4" />
                            </Button>
                            <Button size="lg" variant="outline" className="px-10 h-12 text-base rounded-full gap-2" onClick={() => window.open('https://github.com/dhawalhost/wardseal', '_blank')}>
                                <ExternalLink className="w-4 h-4" /> Read the Docs
                            </Button>
                        </div>
                    </div>
                </section>
            </main>

            {/* ── Footer ──────────────────────────── */}
            <footer className="py-14 px-6 border-t border-border/40 text-sm text-muted-foreground bg-background">
                <div className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-5 gap-8">
                    <div className="col-span-2">
                        <a href="/" className="flex items-center gap-2 mb-4">
                            <div className="w-7 h-7 flex items-center justify-center bg-primary/20 rounded">
                                <img src="/wardseal.svg" alt="WardSeal" className="w-5 h-5 object-contain" />
                            </div>
                            <span className="font-bold text-base text-foreground">WardSeal</span>
                        </a>
                        <p className="max-w-xs mb-4 leading-relaxed">
                            Open-source Identity & Access Management for the modern cloud. SOC 2 ready. OIDC & SAML 2.0 native.
                        </p>
                        <div className="flex gap-3 mt-4">
                            <a href="https://github.com/dhawalhost/wardseal" target="_blank" rel="noreferrer" className="hover:text-primary transition-colors"><Github className="w-4 h-4" /></a>
                            <a href="https://twitter.com/wardseal" target="_blank" rel="noreferrer" className="hover:text-primary transition-colors"><Twitter className="w-4 h-4" /></a>
                            <a href="mailto:hello@wardseal.com" className="hover:text-primary transition-colors"><Mail className="w-4 h-4" /></a>
                        </div>
                    </div>
                    <div>
                        <h4 className="font-semibold text-foreground mb-4">Product</h4>
                        <ul className="space-y-2">
                            <li><a href="#features" className="hover:text-primary transition-colors">Features</a></li>
                            <li><a href="#pricing" className="hover:text-primary transition-colors">Pricing</a></li>
                            <li><a href="#" className="hover:text-primary transition-colors">Changelog</a></li>
                            <li><a href="#" className="hover:text-primary transition-colors">Roadmap</a></li>
                        </ul>
                    </div>
                    <div>
                        <h4 className="font-semibold text-foreground mb-4">Developers</h4>
                        <ul className="space-y-2">
                            <li><a href="#" className="hover:text-primary transition-colors">Documentation</a></li>
                            <li><a href="#" className="hover:text-primary transition-colors">API Reference</a></li>
                            <li><a href="https://github.com/dhawalhost/wardseal" target="_blank" rel="noreferrer" className="hover:text-primary transition-colors">GitHub</a></li>
                            <li><a href="#" className="hover:text-primary transition-colors">Status</a></li>
                        </ul>
                    </div>
                    <div>
                        <h4 className="font-semibold text-foreground mb-4">Company</h4>
                        <ul className="space-y-2">
                            <li><a href="#" className="hover:text-primary transition-colors">About</a></li>
                            <li><a href="mailto:sales@wardseal.com" className="hover:text-primary transition-colors">Sales</a></li>
                            <li><a href="#" className="hover:text-primary transition-colors">Privacy Policy</a></li>
                            <li><a href="#" className="hover:text-primary transition-colors">Terms of Service</a></li>
                        </ul>
                    </div>
                </div>
                <div className="max-w-6xl mx-auto mt-10 pt-6 border-t border-border/40 flex flex-col sm:flex-row justify-between gap-2">
                    <p>&copy; {new Date().getFullYear()} WardSeal Identity, Inc. All rights reserved.</p>
                    <p>Built with ❤ on open standards — OIDC · SAML · SCIM · WebAuthn</p>
                </div>
            </footer>
        </div>
    );
};

export default Landing;
