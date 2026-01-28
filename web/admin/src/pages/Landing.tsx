import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { ArrowRight, ShieldCheck, Lock, Globe, Zap, Server, Code, Check } from 'lucide-react';
import { ModeToggle } from '@/components/mode-toggle';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';

const Landing: React.FC = () => {
    const navigate = useNavigate();

    return (
        <div className="min-h-screen bg-background text-foreground flex flex-col font-sans">
            {/* Header */}
            <header className="px-6 py-4 flex items-center justify-between border-b border-border/40 backdrop-blur-md sticky top-0 z-50 bg-background/80">
                <div className="flex items-center gap-2">
                    <div className="w-8 h-8 flex items-center justify-center bg-primary/20 rounded-lg">
                        <img src="/wardseal.svg" alt="WardSeal" className="w-6 h-6 object-contain" />
                    </div>
                    <span className="font-bold text-xl tracking-tight">WardSeal</span>
                </div>
                <div className="flex items-center gap-4">
                    <nav className="hidden md:flex gap-6 text-sm font-medium text-muted-foreground mr-4">
                        <a href="#features" className="hover:text-foreground transition-colors">Features</a>
                        <a href="#pricing" className="hover:text-foreground transition-colors">Pricing</a>
                        <a href="https://github.com/dhawalhost/wardseal" target="_blank" className="hover:text-foreground transition-colors">Docs</a>
                    </nav>
                    <ModeToggle />
                    <Button variant="ghost" onClick={() => navigate('/login')}>Sign In</Button>
                    <Button onClick={() => navigate('/signup')}>Get Started</Button>
                </div>
            </header>

            {/* Hero Section */}
            <main className="flex-1 flex flex-col">
                <section className="relative flex-1 flex flex-col items-center justify-center text-center px-4 py-24 lg:py-32 overflow-hidden">
                    {/* Background Gradients */}
                    <div className="absolute top-0 left-0 w-full h-full bg-grid-white/[0.02] -z-10" />
                    <div className="absolute -top-24 -left-20 w-96 h-96 bg-primary/20 rounded-full blur-3xl opacity-50 animate-pulse" />
                    <div className="absolute bottom-0 right-0 w-96 h-96 bg-blue-600/20 rounded-full blur-3xl opacity-50 animate-pulse delay-1000" />

                    <div className="max-w-4xl space-y-8 animate-in fade-in slide-in-from-bottom-8 duration-700 relative z-10">
                        <div className="inline-flex items-center rounded-full border border-primary/20 bg-primary/5 px-3 py-1 text-sm font-medium text-primary mb-4 backdrop-blur-sm">
                            <Zap className="w-4 h-4 mr-2 fill-current" /> v1.0 Enterprise Ready
                        </div>
                        <h1 className="text-5xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-foreground leading-tight">
                            Identity Infrastructure for the <br />
                            <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary via-blue-500 to-purple-600">Modern Cloud</span>
                        </h1>
                        <p className="text-xl sm:text-2xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
                            Open source Identity and Access Management (IAM). <br className="hidden sm:block" />
                            Secure your apps with Single Sign-On, MFA, and Zero Trust policies in minutes.
                        </p>
                        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-8">
                            <Button size="lg" className="px-8 h-14 text-lg rounded-full shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow" onClick={() => navigate('/signup?plan=free')}>
                                Start for Free <ArrowRight className="ml-2 w-5 h-5" />
                            </Button>
                            <Button size="lg" variant="outline" className="px-8 h-14 text-lg rounded-full border-primary/20 hover:bg-primary/5" onClick={() => window.open('https://github.com/dhawalhost/wardseal', '_blank')}>
                                <Code className="mr-2 w-5 h-5" /> Star on GitHub
                            </Button>
                        </div>

                        <div className="pt-12 flex justify-center gap-8 text-muted-foreground opacity-60 grayscale hover:grayscale-0 transition-all duration-500">
                            {/* Placeholder logos for social proof */}
                            <div className="flex items-center gap-2"><Server className="w-5 h-5" /> Backend Integrations</div>
                            <div className="flex items-center gap-2"><Globe className="w-5 h-5" /> Web Standards</div>
                            <div className="flex items-center gap-2"><ShieldCheck className="w-5 h-5" /> SOC2 Compliant</div>
                        </div>
                    </div>
                </section>

                {/* Features Grid */}
                <section id="features" className="py-24 px-6 bg-muted/30 border-t border-border/40 relative">
                    <div className="max-w-6xl mx-auto">
                        <div className="text-center mb-16">
                            <h2 className="text-3xl font-bold tracking-tight mb-4">Enterprise-grade Security, Simplified</h2>
                            <p className="text-muted-foreground text-lg max-w-2xl mx-auto">Everything you need to manage users, access, and compliance without the complexity.</p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                            <FeatureCard
                                icon={<ShieldCheck className="w-8 h-8 text-primary" />}
                                title="Enterprise SSO"
                                description="Secure access to all your apps with OIDC and SAML 2.0 support. Built-in multi-tenancy and organization management."
                            />
                            <FeatureCard
                                icon={<Lock className="w-8 h-8 text-primary" />}
                                title="Zero Trust Security"
                                description="Device posture checks, continuous access evaluation, and risk-based authentication policies."
                            />
                            <FeatureCard
                                icon={<Globe className="w-8 h-8 text-primary" />}
                                title="Identity Governance"
                                description="Automated access reviews, request workflows, and audit logging for comprehensive compliance."
                            />
                            <FeatureCard
                                icon={<Code className="w-8 h-8 text-primary" />}
                                title="Developer First"
                                description="Simple APIs, SDKs, and granular permission controls designed for modern application development."
                            />
                            <FeatureCard
                                icon={<Zap className="w-8 h-8 text-primary" />}
                                title="Passwordless"
                                description="Support for Passkeys (WebAuthn), Magic Links, and Social Login to reduce friction and increase security."
                            />
                            <FeatureCard
                                icon={<Server className="w-8 h-8 text-primary" />}
                                title="Hybrid Deployment"
                                description="Deploy on our cloud or self-host in your own infrastructure. You own your data."
                            />
                        </div>
                    </div>
                </section>

                {/* Pricing Section */}
                <section id="pricing" className="py-24 px-6 relative">
                    <div className="max-w-5xl mx-auto">
                        <div className="text-center mb-16">
                            <h2 className="text-3xl font-bold tracking-tight mb-4">Simple, Transparent Pricing</h2>
                            <p className="text-muted-foreground text-lg">Start for free, scale with your needs.</p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-start">
                            {/* Free Tier */}
                            <Card className="border-primary/20 shadow-lg relative overflow-hidden">
                                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-primary to-transparent" />
                                <CardHeader>
                                    <CardTitle className="text-2xl">Free Tier</CardTitle>
                                    <CardDescription>Perfect for startups and developers.</CardDescription>
                                    <div className="mt-4">
                                        <span className="text-4xl font-bold">$0</span>
                                        <span className="text-muted-foreground">/month</span>
                                    </div>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    <ul className="space-y-3">
                                        <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-green-500" /> Unlimited Users (Launch Offer)</li>
                                        <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-green-500" /> Up to 3 Applications</li>
                                        <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-green-500" /> Social Login (Google, GitHub)</li>
                                        <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-green-500" /> Community Support</li>
                                        <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-green-500" /> Cloud Hosted</li>
                                    </ul>
                                </CardContent>
                                <CardFooter>
                                    <Button className="w-full" onClick={() => navigate('/signup?plan=free')}>Get Started Free</Button>
                                </CardFooter>
                            </Card>

                            {/* Enterprise Tier */}
                            <Card className="border-border bg-muted/10">
                                <CardHeader>
                                    <CardTitle className="text-2xl">Enterprise</CardTitle>
                                    <CardDescription>For large organizations requiring control.</CardDescription>
                                    <div className="mt-4">
                                        <span className="text-4xl font-bold">Custom</span>
                                        <span className="text-muted-foreground">/license</span>
                                    </div>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    <ul className="space-y-3">
                                        <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-primary" /> Everything in Free</li>
                                        <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-primary" /> Unlimited Applications</li>
                                        <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-primary" /> SAML & OIDC Federation</li>
                                        <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-primary" /> Audit Logs & Compliance Reports</li>
                                        <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-primary" /> Self-Hosted / Private Cloud</li>
                                        <li className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-primary" /> Priority Support & SLA</li>
                                    </ul>
                                </CardContent>
                                <CardFooter>
                                    <Button variant="outline" className="w-full" onClick={() => window.location.href = 'mailto:sales@wardseal.com'}>Contact Sales</Button>
                                </CardFooter>
                            </Card>
                        </div>
                    </div>
                </section>

                {/* CTA Section */}
                <section className="py-24 px-6 bg-primary/5 text-center">
                    <div className="max-w-3xl mx-auto space-y-6">
                        <h2 className="text-3xl font-bold tracking-tight">Ready to secure your users?</h2>
                        <p className="text-lg text-muted-foreground">Join thousands of developers building secure applications with WardSeal.</p>
                        <Button size="lg" className="px-8 h-12 text-base rounded-full" onClick={() => navigate('/signup')}>
                            Create Free Account
                        </Button>
                    </div>
                </section>
            </main>

            {/* Footer */}
            <footer className="py-12 px-6 border-t border-border/40 text-sm text-muted-foreground bg-background">
                <div className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8">
                    <div className="col-span-2">
                        <div className="flex items-center gap-2 mb-4">
                            <div className="w-6 h-6 flex items-center justify-center bg-primary/20 rounded">
                                <img src="/wardseal.svg" alt="WardSeal" className="w-4 h-4 object-contain" />
                            </div>
                            <span className="font-bold text-lg text-foreground">WardSeal</span>
                        </div>
                        <p className="max-w-xs mb-4">The open source identity platform for modern applications.</p>
                        <p>&copy; {new Date().getFullYear()} WardSeal Identity.</p>
                    </div>
                    <div>
                        <h4 className="font-semibold text-foreground mb-4">Product</h4>
                        <ul className="space-y-2">
                            <li><a href="#" className="hover:text-primary">Features</a></li>
                            <li><a href="#" className="hover:text-primary">Integrations</a></li>
                            <li><a href="#" className="hover:text-primary">Pricing</a></li>
                            <li><a href="#" className="hover:text-primary">Roadmap</a></li>
                        </ul>
                    </div>
                    <div>
                        <h4 className="font-semibold text-foreground mb-4">Resources</h4>
                        <ul className="space-y-2">
                            <li><a href="#" className="hover:text-primary">Documentation</a></li>
                            <li><a href="#" className="hover:text-primary">API Reference</a></li>
                            <li><a href="#" className="hover:text-primary">GitHub</a></li>
                            <li><a href="#" className="hover:text-primary">Community</a></li>
                        </ul>
                    </div>
                </div>
            </footer>
        </div>
    );
};

const FeatureCard = ({ icon, title, description }: { icon: React.ReactNode, title: string, description: string }) => (
    <div className="p-6 rounded-2xl bg-card border border-border/50 shadow-sm hover:shadow-lg hover:border-primary/20 transition-all duration-300 group">
        <div className="mb-4 p-3 bg-primary/5 rounded-xl w-fit group-hover:bg-primary/10 transition-colors">{icon}</div>
        <h3 className="text-xl font-semibold mb-2">{title}</h3>
        <p className="text-muted-foreground leading-relaxed">{description}</p>
    </div>
);

export default Landing;
