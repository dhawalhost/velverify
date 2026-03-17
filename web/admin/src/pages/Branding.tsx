import React, { useState, useEffect } from 'react';
import { getBranding, updateBranding, BrandingConfig } from '../api';
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Loader2, Save, Palette, RefreshCw, LayoutTemplate } from 'lucide-react';
import { Separator } from '@/components/ui/separator';

import { Badge } from '@/components/ui/badge';

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

    if (loading) return <div className="p-8 flex items-center justify-center h-96"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>;

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Branding</h1>
                    <p className="text-muted-foreground mt-1">
                        Customize the look and feel of your login experience.
                    </p>
                </div>
                <div className="flex gap-2">
                    <Button variant="outline" onClick={loadBranding} title="Reset to saved">
                        <RefreshCw className="h-4 w-4" />
                    </Button>
                </div>
            </div>

            <Separator className="my-4" />

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">

                {/* SETTINGS COLUMN */}
                <div className="lg:col-span-5 space-y-6">
                    <Card className="shadow-sm border-muted/60">
                        <CardHeader>
                            <div className="flex items-center gap-2 mb-1">
                                <div className="p-2 bg-primary/10 rounded-md text-primary">
                                    <LayoutTemplate className="h-4 w-4" />
                                </div>
                                <CardTitle className="text-lg">Appearance</CardTitle>
                            </div>
                            <CardDescription>Configure basic visual elements.</CardDescription>
                        </CardHeader>
                        <CardContent>
                            <form id="branding-form" onSubmit={handleSave} className="space-y-6">
                                <div className="space-y-2">
                                    <Label htmlFor="logo">Logo URL</Label>
                                    <div className="relative">
                                        <Input
                                            id="logo"
                                            type="url"
                                            value={config.logo_url}
                                            onChange={e => setConfig({ ...config, logo_url: e.target.value })}
                                            placeholder="https://..."
                                            className="pl-9"
                                        />
                                        <div className="absolute left-3 top-2.5 text-muted-foreground">
                                            <Palette className="h-4 w-4" />
                                        </div>
                                        <p className="text-[10px] text-muted-foreground mt-1.5 ml-1">Recommend SVG or transparent PNG.</p>
                                    </div>
                                </div>
                                <div className="grid grid-cols-2 gap-6">
                                    <div className="space-y-2">
                                        <Label htmlFor="primary">Accent Color</Label>
                                        <div className="flex items-center gap-3">
                                            <div className="relative">
                                                <Input
                                                    id="primary"
                                                    type="color"
                                                    value={config.primary_color}
                                                    onChange={e => setConfig({ ...config, primary_color: e.target.value })}
                                                    className="w-10 h-10 p-0.5 rounded-md cursor-pointer border-2"
                                                />
                                            </div>
                                            <Input
                                                value={config.primary_color}
                                                onChange={e => setConfig({ ...config, primary_color: e.target.value })}
                                                className="uppercase font-mono text-xs tracking-wider"
                                                maxLength={7}
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="bg">Background</Label>
                                        <div className="flex items-center gap-3">
                                            <div className="relative">
                                                <Input
                                                    id="bg"
                                                    type="color"
                                                    value={config.background_color}
                                                    onChange={e => setConfig({ ...config, background_color: e.target.value })}
                                                    className="w-10 h-10 p-0.5 rounded-md cursor-pointer border-2"
                                                />
                                            </div>
                                            <Input
                                                value={config.background_color}
                                                onChange={e => setConfig({ ...config, background_color: e.target.value })}
                                                className="uppercase font-mono text-xs tracking-wider"
                                                maxLength={7}
                                            />
                                        </div>
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="css">Custom CSS</Label>
                                    <Textarea
                                        id="css"
                                        value={config.css_override}
                                        onChange={e => setConfig({ ...config, css_override: e.target.value })}
                                        rows={6}
                                        placeholder=".login-card { border-radius: 0; }"
                                        className="font-mono text-xs leading-relaxed bg-muted/20 resize-none"
                                    />
                                    <p className="text-[10px] text-muted-foreground mt-1 ml-1">Advanced customization for the login page.</p>
                                </div>
                            </form>
                        </CardContent>
                        <CardFooter className="flex flex-col items-start gap-4 border-t bg-muted/10 p-6">
                            {error && (
                                <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 p-2 rounded w-full">
                                    <div className="h-4 w-4 bg-destructive rounded-full" />
                                    {error}
                                </div>
                            )}
                            {success && (
                                <div className="flex items-center gap-2 text-sm text-green-600 bg-green-50 p-2 rounded w-full border border-green-200">
                                    <div className="h-1.5 w-1.5 bg-green-500 rounded-full ml-1" />
                                    {success}
                                </div>
                            )}
                            <Button type="submit" form="branding-form" disabled={saving} className="w-full">
                                {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                                Save Changes
                            </Button>
                        </CardFooter>
                    </Card>
                </div>

                {/* PREVIEW COLUMN */}
                <div className="lg:col-span-7 sticky top-6">
                    <Card className="shadow-sm border-muted/60 bg-muted/20 overflow-hidden">
                        <CardHeader className="border-b bg-background/50 backdrop-blur-sm">
                            <CardTitle className="text-sm font-medium flex items-center justify-between">
                                <span>Live Preview</span>
                                <Badge variant="outline" className="text-xs font-normal">Login Page</Badge>
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="p-0">
                            {/* PREVIEW FRAME */}
                            <div
                                className="h-[600px] w-full flex items-center justify-center p-8 transition-colors duration-500 relative"
                                style={{ backgroundColor: config.background_color }}
                            >
                                {/* Grid Pattern Overlay for style */}
                                <div className="absolute inset-0 opacity-[0.03]"
                                    style={{
                                        backgroundImage: `linear-gradient(#000 1px, transparent 1px), linear-gradient(90deg, #000 1px, transparent 1px)`,
                                        backgroundSize: '20px 20px'
                                    }}
                                />

                                {/* Mock Login Card */}
                                <div className="w-full max-w-[400px] bg-white rounded-xl shadow-xl border p-8 relative z-10 animate-in zoom-in-95 duration-500">
                                    <div className="text-center mb-8">
                                        {config.logo_url ? (
                                            <img src={config.logo_url} alt="Logo" className="mx-auto h-12 mb-6 object-contain" />
                                        ) : (
                                            <div className="mx-auto h-12 w-12 bg-gray-100 rounded-xl flex items-center justify-center mb-6">
                                                <Palette className="h-6 w-6 text-gray-400" />
                                            </div>
                                        )}
                                        <h2 className="text-2xl font-bold text-gray-900 tracking-tight">Welcome back</h2>
                                        <p className="text-sm text-gray-500 mt-2">Enter your credentials to continue</p>
                                    </div>

                                    <div className="space-y-4">
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-gray-700">Email address</label>
                                            <div className="h-10 w-full rounded-md border border-gray-200 bg-gray-50 px-3 py-2 text-sm text-gray-500 flex items-center select-none">
                                                user@wardseal.com
                                            </div>
                                        </div>
                                        <div className="space-y-2">
                                            <div className="flex justify-between">
                                                <label className="text-sm font-medium text-gray-700">Password</label>
                                                <span className="text-xs text-blue-600 cursor-pointer">Forgot?</span>
                                            </div>
                                            <div className="h-10 w-full rounded-md border border-gray-300 bg-white px-3 py-2"></div>
                                        </div>

                                        <button
                                            className="w-full h-10 rounded-md text-white font-medium text-sm transition-all shadow-sm hover:opacity-90 active:scale-[0.98] mt-2"
                                            style={{ backgroundColor: config.primary_color }}
                                        >
                                            Sign In
                                        </button>

                                        <div className="relative my-6">
                                            <div className="absolute inset-0 flex items-center"><span className="w-full border-t border-gray-200" /></div>
                                            <div className="relative flex justify-center text-xs uppercase"><span className="bg-white px-2 text-gray-400">Or continue with</span></div>
                                        </div>

                                        <div className="grid grid-cols-2 gap-3">
                                            <div className="h-9 border rounded flex items-center justify-center hover:bg-gray-50 cursor-pointer transition-colors">
                                                <svg className="h-4 w-4" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" /><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" /><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" /><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" /></svg>
                                            </div>
                                            <div className="h-9 border rounded flex items-center justify-center hover:bg-gray-50 cursor-pointer transition-colors">
                                                <span className="text-xs font-medium text-gray-600">SSO</span>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="mt-8 text-center">
                                        <p className="text-xs text-gray-400">Protected by WardSeal Identity</p>
                                    </div>
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    );
};

export default Branding;
