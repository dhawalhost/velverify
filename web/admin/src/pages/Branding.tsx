import React, { useState, useEffect } from 'react';
import { getBranding, updateBranding, BrandingConfig } from '../api';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Loader2, Save, Palette, RefreshCw, LayoutTemplate } from 'lucide-react';
import { Separator } from '@/components/ui/separator';

import { Badge } from '@/components/ui/badge';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassCardDescription } from '@/components/layout';

const Branding: React.FC = () => {
    const [config, setConfig] = useState<BrandingConfig>({
        tenant_id: '',
        logo_url: '/wardseal.svg', // Default
        primary_color: '#0e1c3a', // Default Navy
        background_color: '#F4F7FB', // Default Light Gray
        css_override: '',
        config: {}
    });
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    useEffect(() => {
        loadBranding();
    }, []);

    const loadBranding = async () => {
        try {
            const data = await getBranding();
            // initialize with defaults if empty properties
            setConfig(prev => ({
                ...data,
                primary_color: data.primary_color || prev.primary_color,
                background_color: data.background_color || prev.background_color,
                logo_url: data.logo_url || prev.logo_url
            }));
        } catch (err) {
            console.error(err);
            // Ignore 404/empty, just keep defaults
        } finally {
            setLoading(false);
        }
    };

    const handleSave = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setSuccess('');
        setSaving(true);
        try {
            await updateBranding(config);
            setSuccess('Branding updated successfully!');
            setTimeout(() => setSuccess(''), 3000);
        } catch (err: any) {
            setError('Failed to update branding');
            console.error(err);
        } finally {
            setSaving(false);
        }
    };

    if (loading) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="space-y-12 animate-in fade-in duration-700">
            <PageHeader
                icon={<Palette className="w-10 h-10 text-primary" />}
                title="Branding"
                description="Customize the design of your login page and user portal."
                actions={
                    <Button
                        variant="outline"
                        onClick={loadBranding}
                        className="h-11 rounded-xl bg-card ring-1 ring-on-surface/5 font-bold text-sm px-8 shadow-sm transition-all hover:bg-surface-container"
                    >
                        <RefreshCw className="h-4 w-4 mr-3" /> Reset Design
                    </Button>
                }
            />

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-start">
                {/* SETTINGS COLUMN */}
                <div className="lg:col-span-5 space-y-8">
                    <GlassCard className="shadow-on-surface/10">
                        <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5 bg-surface-container/10">
                            <div className="flex items-center gap-6">
                                <div className="p-4 bg-primary rounded-2xl text-white shadow-lg shadow-primary/20">
                                    <LayoutTemplate className="w-7 h-7" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface">Design Settings</GlassCardTitle>
                                    <p className="text-on-surface-variant/60 font-medium text-[12px] mt-2 italic">Configure your brand colors and logo.</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-10">
                            <form id="branding-form" onSubmit={handleSave} className="space-y-10">
                                <div className="space-y-4">
                                    <Label htmlFor="logo" className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                        <Palette className="w-3.5 h-3.5" />
                                        Logo URL
                                    </Label>
                                    <div className="relative">
                                        <div className="absolute left-4 top-1/2 -translate-y-1/2 text-on-surface-variant/40">
                                            <Palette className="h-5 w-5" />
                                        </div>
                                        <Input
                                            id="logo"
                                            type="url"
                                            value={config.logo_url}
                                            onChange={e => setConfig({ ...config, logo_url: e.target.value })}
                                            placeholder="https://your-domain.com/logo.svg"
                                            className="h-14 border-none rounded-2xl bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-6"
                                        />
                                        <p className="text-[10px] font-medium text-on-surface-variant/40 mt-3 ml-1 italic">Recommended: Use an SVG or PNG with a transparent background.</p>
                                    </div>
                                </div>

                                <div className="grid grid-cols-2 gap-8">
                                    <div className="space-y-4">
                                        <Label htmlFor="primary" className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Primary Color</Label>
                                        <div className="flex items-center gap-4">
                                            <Input
                                                id="primary"
                                                type="color"
                                                value={config.primary_color}
                                                onChange={e => setConfig({ ...config, primary_color: e.target.value })}
                                                className="w-14 h-14 p-1 rounded-xl cursor-pointer border-none bg-surface-container/50 ring-1 ring-on-surface/5 shadow-sm transition-all"
                                            />
                                            <Input
                                                value={config.primary_color}
                                                onChange={e => setConfig({ ...config, primary_color: e.target.value })}
                                                className="uppercase font-mono text-xs font-bold tracking-widest h-14 rounded-xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 px-4"
                                                maxLength={7}
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-4">
                                        <Label htmlFor="bg" className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Background Color</Label>
                                        <div className="flex items-center gap-4">
                                            <Input
                                                id="bg"
                                                type="color"
                                                value={config.background_color}
                                                onChange={e => setConfig({ ...config, background_color: e.target.value })}
                                                className="w-14 h-14 p-1 rounded-xl cursor-pointer border-none bg-surface-container/50 ring-1 ring-on-surface/5 shadow-sm transition-all"
                                            />
                                            <Input
                                                value={config.background_color}
                                                onChange={e => setConfig({ ...config, background_color: e.target.value })}
                                                className="uppercase font-mono text-xs font-bold tracking-widest h-14 rounded-xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 px-4"
                                                maxLength={7}
                                            />
                                        </div>
                                    </div>
                                </div>

                                <div className="space-y-4">
                                     <Label htmlFor="css" className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Custom CSS</Label>
                                    <Textarea
                                        id="css"
                                        value={config.css_override}
                                        onChange={e => setConfig({ ...config, css_override: e.target.value })}
                                        rows={8}
                                        placeholder=".LOGIN-CARD { border: 2px solid var(--primary); }"
                                        className="flex min-h-[200px] w-full border-none rounded-2xl bg-surface-container/50 ring-1 ring-on-surface/5 p-6 font-mono text-[11px] leading-relaxed focus:outline-none focus:ring-2 focus:ring-primary/20 custom-scrollbar-dark text-on-surface"
                                    />
                                    <p className="text-[11px] font-medium text-on-surface-variant/40 mt-3 ml-1 italic">Add custom CSS to further customize the login experience.</p>
                                </div>

                                <div className="pt-6">
                                     {error && (
                                        <div className="flex items-center gap-4 text-[12px] font-bold text-destructive bg-destructive/10 p-5 rounded-2xl border border-destructive/20 mb-6 animate-in slide-in-from-top-2">
                                            <div className="h-2 w-2 bg-destructive rounded-full animate-pulse" />
                                            Error: {error}
                                        </div>
                                    )}
                                    {success && (
                                        <div className="flex items-center gap-4 text-[12px] font-bold text-success bg-success-subtle p-5 rounded-2xl border border-success/10 mb-6 animate-in slide-in-from-top-2">
                                            <div className="h-2 w-2 bg-success rounded-full animate-pulse" />
                                            Success: {success}
                                        </div>
                                    )}
                                    <Button
                                        type="submit"
                                        form="branding-form"
                                        disabled={saving}
                                        className="w-full h-14 rounded-2xl font-bold text-sm shadow-xl shadow-primary/20 transition-all group"
                                    >
                                        {saving ? <Loader2 className="mr-3 h-5 w-5 animate-spin" /> : <Save className="mr-3 h-5 w-5" />}
                                        Save Branding
                                    </Button>
                                </div>
                            </form>
                        </GlassCardContent>
                    </GlassCard>
                </div>

                {/* PREVIEW COLUMN */}
                <div className="lg:col-span-7 lg:sticky lg:top-8">
                    <GlassCard className="shadow-on-surface/5 flex flex-col h-full overflow-hidden">
                        <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5">
                            <div className="flex items-center justify-between">
                                <div>
                                    <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">Preview</GlassCardTitle>
                                    <p className="text-on-surface-variant/60 font-medium text-[11px] mt-1.5 italic">See how your changes will look for users.</p>
                                </div>
                                <Badge className="bg-success/10 text-success border-none rounded-lg font-bold text-[9px] tracking-tight px-3 py-1 uppercase italic">Live Preview</Badge>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-0 bg-surface-container/30">
                            <div
                                className="h-[740px] w-full flex items-center justify-center p-12 transition-all duration-700 relative overflow-hidden"
                                style={{ backgroundColor: config.background_color }}
                            >
                                <div className="absolute inset-0 opacity-[0.03]"
                                    style={{
                                        backgroundImage: `linear-gradient(hsl(var(--on-surface)) 1px, transparent 1px), linear-gradient(90deg, hsl(var(--on-surface)) 1px, transparent 1px)`,
                                        backgroundSize: '30px 30px'
                                    }}
                                />

                                <div className="w-full max-w-[460px] bg-card rounded-[32px] border-none p-14 relative z-10 shadow-2xl shadow-on-surface/10 animate-in zoom-in-95 duration-700">
                                    <div className="text-center mb-14">
                                        {config.logo_url ? (
                                            <img src={config.logo_url} alt="Logo" className="mx-auto h-16 min-w-[80px] mb-8 object-contain" />
                                        ) : (
                                            <div className="mx-auto h-16 w-16 bg-primary/5 rounded-2xl flex items-center justify-center mb-8">
                                                <Palette className="h-8 w-8 text-primary" />
                                            </div>
                                        )}
                                        <h2 className="text-3xl font-bold text-on-surface tracking-tight leading-none">Authentication</h2>
                                        <p className="text-[11px] font-bold text-on-surface-variant/40 mt-6 leading-none italic">Secure login</p>
                                    </div>

                                    <div className="space-y-6">
                                        <div className="space-y-3">
                                            <label className="text-[11px] font-bold text-on-surface-variant/40 ml-1">Email Address</label>
                                            <div className="h-14 w-full rounded-2xl bg-surface-container/50 ring-1 ring-on-surface/5 px-6 py-2 text-sm text-on-surface font-medium flex items-center select-none shadow-sm">
                                                admin@wardseal.io
                                            </div>
                                        </div>
                                        <div className="space-y-3">
                                            <div className="flex justify-between items-end">
                                                <label className="text-[11px] font-bold text-on-surface-variant/40 ml-1">Password</label>
                                                <span className="text-[11px] font-bold text-primary cursor-pointer hover:underline underline-offset-4 italic">Forgot password?</span>
                                            </div>
                                            <div className="h-14 w-full rounded-2xl bg-surface-container/50 ring-1 ring-on-surface/5 px-6 py-2 flex items-center shadow-sm">
                                                <div className="flex gap-2 opacity-10">
                                                    {[1, 2, 3, 4, 5, 6, 7, 8].map(i => <div key={i} className="w-2 h-2 bg-on-surface rounded-full" />)}
                                                </div>
                                            </div>
                                        </div>

                                        <button
                                            className="w-full h-16 rounded-2xl text-white font-bold text-sm transition-all active:scale-[0.98] mt-4 shadow-lg shadow-on-surface/10"
                                            style={{ backgroundColor: config.primary_color }}
                                        >
                                            Sign In
                                        </button>

                                        <div className="relative my-10">
                                            <div className="absolute inset-0 flex items-center"><span className="w-full border-t border-on-surface/5" /></div>
                                            <div className="relative flex justify-center text-[11px] font-bold"><span className="bg-card px-6 text-on-surface-variant/20 italic">Or sign in with</span></div>
                                        </div>

                                        <div className="grid grid-cols-1 gap-4">
                                            <div className="h-14 rounded-2xl ring-1 ring-on-surface/5 bg-card text-on-surface flex items-center justify-center hover:bg-surface-container cursor-pointer transition-all font-bold text-[12px] shadow-sm italic">
                                                Sign in with SSO
                                            </div>
                                        </div>
                                    </div>

                                    <div className="mt-12 text-center border-t border-on-surface/5 pt-8">
                                        <p className="text-[11px] font-bold text-on-surface-variant/20 italic">Powered by WardSeal</p>
                                    </div>
                                </div>
                            </div>
                        </GlassCardContent>
                    </GlassCard>
                </div>
            </div>
        </div >
    );
};

export default Branding;
