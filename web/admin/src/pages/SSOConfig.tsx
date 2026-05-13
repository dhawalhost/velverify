import { useState, useEffect } from 'react';
import { getSSOProviders, createSSOProvider, updateSSOProvider, deleteSSOProvider, toggleSSOProvider } from '../api';
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Plus, Trash2, Edit, ShieldCheck, Lock, Fingerprint, Activity, Terminal, ArrowLeft, Loader2, Building2 } from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow, GlassCardDescription } from '@/components/layout';

interface SSOProvider {
    id: string;
    name: string;
    type: 'oidc' | 'saml';
    enabled: boolean;

    // OIDC
    oidc_issuer_url?: string;
    oidc_client_id?: string;
    oidc_client_secret?: string;
    oidc_scopes?: string;

    // SAML
    saml_entity_id?: string;
    saml_sso_url?: string;
    saml_slo_url?: string;
    saml_certificate?: string;
    saml_sign_requests?: boolean;
    saml_sign_assertions?: boolean;
    saml_encrypt_assertions?: boolean;

    auto_create_users: boolean;
}

export default function SSOConfig() {
    const [providers, setProviders] = useState<SSOProvider[]>([]);
    const [loading, setLoading] = useState(true);
    const [editingProvider, setEditingProvider] = useState<Partial<SSOProvider> | null>(null);
    const [isCreating, setIsCreating] = useState(false);

    useEffect(() => {
        loadProviders();
    }, []);

    const loadProviders = async () => {
        try {
            const res = await getSSOProviders();
            setProviders(res.providers || []);
        } catch (error) {
            console.error('Failed to load providers:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleSave = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!editingProvider) return;

        try {
            if (isCreating) {
                await createSSOProvider(editingProvider);
            } else if (editingProvider.id) {
                await updateSSOProvider(editingProvider.id, editingProvider);
            }
            setEditingProvider(null);
            setIsCreating(false);
            loadProviders();
        } catch (error) {
            console.error('Failed to save provider:', error);
        }
    };

    const handleDelete = async (id: string) => {
        if (confirm('Are you sure you want to delete this provider?')) {
            try {
                await deleteSSOProvider(id);
                loadProviders();
            } catch (error) {
                console.error('Failed to delete provider:', error);
            }
        }
    };

    const handleToggle = async (id: string, enabled: boolean) => {
        try {
            await toggleSSOProvider(id, enabled);
            loadProviders();
        } catch (error) {
            console.error('Failed to toggle provider:', error);
        }
    };

    if (loading) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="space-y-12 animate-in fade-in duration-700">
            <PageHeader
                icon={<Building2 className="w-8 h-8 text-primary" />}
                title="Single Sign-On (SSO)"
                description="Configure SSO to allow users to sign in using their existing identity provider. Support SAML, OIDC, and other standard protocols."
                actions={
                    !editingProvider && (
                        <div className="flex gap-2">
                            <Button
                                onClick={() => { setEditingProvider({ type: 'oidc', enabled: true, auto_create_users: true }); setIsCreating(true); }}
                                className="h-9 rounded-lg font-bold text-[11px] tracking-tight px-6 shadow-sm transition-all"
                            >
                                <Plus className="mr-2 h-3.5 w-3.5" /> Integrate OIDC
                            </Button>
                            <Button
                                variant="outline"
                                onClick={() => { setEditingProvider({ type: 'saml', enabled: true, auto_create_users: true }); setIsCreating(true); }}
                                className="h-9 rounded-lg bg-card ring-1 ring-on-surface/5 font-bold text-[11px] tracking-tight px-6 shadow-sm transition-all hover:bg-surface-container"
                            >
                                <Plus className="mr-2 h-3.5 w-3.5" /> Integrate SAML
                            </Button>
                        </div>
                    )
                }
            />

            {!editingProvider ? (
                <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                    <GlassCardHeader className="py-4 px-6 border-b border-on-surface/5">
                        <div className="flex items-center gap-3">
                            <div className="p-2 bg-primary/5 rounded-lg">
                                <ShieldCheck className="w-5 h-5 text-primary" />
                            </div>
                            <div>
                                <GlassCardTitle className="text-lg font-bold tracking-tight text-on-surface">SSO Configurations</GlassCardTitle>
                                <p className="text-on-surface-variant/40 font-bold text-[10px] mt-0.5 tracking-tight">
                                    {providers.length} Active Identity Providers
                                </p>
                            </div>
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="p-0">
                        <div className="overflow-x-auto">
                            <GlassTable>
                                <GlassTableHeader>
                                    <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                        <GlassTableHead className="py-3 pl-6 font-bold text-[10px] tracking-tight text-on-surface-variant/40 uppercase">Provider Name</GlassTableHead>
                                        <GlassTableHead className="py-3 font-bold text-[10px] tracking-tight text-on-surface-variant/40 uppercase">Protocol</GlassTableHead>
                                        <GlassTableHead className="py-3 font-bold text-[10px] tracking-tight text-on-surface-variant/40 uppercase">Status</GlassTableHead>
                                        <GlassTableHead className="py-3 text-right font-bold text-[10px] tracking-tight text-on-surface-variant/40 pr-6 uppercase">Actions</GlassTableHead>
                                    </GlassTableRow>
                                </GlassTableHeader>
                                <TableBody>
                                    {providers.length === 0 ? (
                                        <GlassTableRow>
                                            <TableCell colSpan={4} className="py-32 text-center text-sm font-medium text-on-surface-variant/30 italic">
                                                No SSO infrastructure established. Federation awaiting deployment.
                                            </TableCell>
                                        </GlassTableRow>
                                    ) : (
                                        providers.map(p => (
                                            <GlassTableRow key={p.id} className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                                <TableCell className="py-3 pl-6">
                                                    <span className="text-sm font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{p.name}</span>
                                                </TableCell>
                                                <TableCell className="py-3">
                                                    <Badge className={`rounded-md font-bold text-[9px] tracking-tight border-none px-2 py-0.5 transition-all ${p.type === 'oidc' ? 'bg-primary/10 text-primary' : 'bg-amber-500/10 text-amber-600'}`}>
                                                        {p.type.toUpperCase()}
                                                    </Badge>
                                                </TableCell>
                                                <TableCell className="py-3">
                                                    <div className="flex items-center gap-3">
                                                        <Switch
                                                            checked={p.enabled}
                                                            onCheckedChange={(checked) => handleToggle(p.id, checked)}
                                                            className="h-4 w-7 data-[state=checked]:bg-success"
                                                        />
                                                        <span className={`text-[9px] font-bold tracking-tight transition-all uppercase ${p.enabled ? 'text-success' : 'text-on-surface-variant/40'}`}>
                                                            {p.enabled ? 'Live' : 'Inactive'}
                                                        </span>
                                                    </div>
                                                </TableCell>
                                                <TableCell className="py-3 text-right pr-6">
                                                    <div className="flex justify-end gap-1.5">
                                                        <Button size="icon" variant="ghost" className="h-8 w-8 rounded-lg text-on-surface-variant/40 hover:text-on-surface hover:bg-surface-container transition-all" onClick={() => { setEditingProvider(p); setIsCreating(false); }}>
                                                            <Edit className="h-4 w-4" />
                                                        </Button>
                                                        <Button size="icon" variant="ghost" className="h-8 w-8 rounded-lg text-on-surface-variant/40 hover:text-destructive hover:bg-destructive/10 transition-all" onClick={() => handleDelete(p.id)}>
                                                            <Trash2 className="h-4 w-4" />
                                                        </Button>
                                                    </div>
                                                </TableCell>
                                            </GlassTableRow>
                                        ))
                                    )}
                                </TableBody>
                            </GlassTable>
                        </div>
                    </GlassCardContent>
                </GlassCard>
            ) : (
                <GlassCard className="max-w-4xl mx-auto border-none shadow-2xl shadow-on-surface/10 bg-card overflow-hidden rounded-xl">
                    <GlassCardHeader className="py-6 px-8 border-b border-on-surface/5 bg-surface-container/10">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-4">
                                <div className="p-3 bg-primary rounded-xl text-white shadow-lg shadow-primary/20">
                                    <Fingerprint className="w-6 h-6" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">
                                        {isCreating ? 'Provision' : 'Architect'} {editingProvider.type?.toUpperCase()}
                                    </GlassCardTitle>
                                    <p className="text-on-surface-variant/60 font-medium text-[10px] mt-1 italic">Configure federation tunnel protocol logic.</p>
                                </div>
                            </div>
                            <Button
                                variant="outline"
                                size="sm"
                                className="bg-card rounded-lg font-bold text-[10px] h-8 px-4 ring-1 ring-on-surface/5 shadow-sm hover:bg-surface-container transition-all"
                                onClick={() => setEditingProvider(null)}
                            >
                                <ArrowLeft className="mr-2 h-3.5 w-3.5" /> Cancel
                            </Button>
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="p-8 space-y-6">
                        <form id="sso-form" onSubmit={handleSave} className="space-y-6">
                            <div className="space-y-3">
                                <Label htmlFor="name" className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 italic">01 // Operational alias</Label>
                                <Input
                                    id="name"
                                    value={editingProvider.name || ''}
                                    onChange={(e) => setEditingProvider({ ...editingProvider, name: e.target.value })}
                                    required
                                    className="h-10 border-none rounded-xl bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-medium px-4 text-sm"
                                    placeholder="e.g., Okta Enterprise"
                                />
                            </div>

                            <div className="h-px bg-on-surface/5" />

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                {editingProvider.type === 'oidc' && (
                                    <>
                                        <div className="space-y-4 md:col-span-2">
                                            <Label htmlFor="issuer" className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1 italic">02 // Discovery endpoint</Label>
                                            <div className="relative">
                                                <Activity className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-on-surface-variant/40" />
                                                <Input
                                                    id="issuer"
                                                    type="url"
                                                    value={editingProvider.oidc_issuer_url || ''}
                                                    onChange={(e) => setEditingProvider({ ...editingProvider, oidc_issuer_url: e.target.value })}
                                                    required
                                                    className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs pl-12"
                                                    placeholder="https://idp.discovery.url"
                                                />
                                            </div>
                                        </div>
                                        <div className="space-y-4">
                                            <Label htmlFor="client_id" className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1 italic">03 // Handshake uid</Label>
                                            <Input
                                                id="client_id"
                                                value={editingProvider.oidc_client_id || ''}
                                                onChange={(e) => setEditingProvider({ ...editingProvider, oidc_client_id: e.target.value })}
                                                required
                                                className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs px-5"
                                                placeholder="Client ID"
                                            />
                                        </div>
                                        <div className="space-y-4">
                                            <Label htmlFor="client_secret" className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1 italic">04 // Secret entropy {isCreating ? '' : '(locked)'}</Label>
                                            <Input
                                                id="client_secret"
                                                type="password"
                                                value={editingProvider.oidc_client_secret || ''}
                                                onChange={(e) => setEditingProvider({ ...editingProvider, oidc_client_secret: e.target.value })}
                                                required={isCreating}
                                                className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all text-xs px-5"
                                                placeholder="••••••••••••••••"
                                            />
                                        </div>
                                        <div className="space-y-4 md:col-span-2">
                                            <Label htmlFor="scopes" className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1 italic">05 // Claim scopes</Label>
                                            <Input
                                                id="scopes"
                                                value={editingProvider.oidc_scopes || 'openid profile email'}
                                                onChange={(e) => setEditingProvider({ ...editingProvider, oidc_scopes: e.target.value })}
                                                className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs px-5"
                                            />
                                        </div>
                                    </>
                                )}

                                {editingProvider.type === 'saml' && (
                                    <>
                                        <div className="space-y-4 md:col-span-2">
                                            <Label htmlFor="entity_id" className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1 italic">02 // Subject identifier</Label>
                                            <Input
                                                id="entity_id"
                                                value={editingProvider.saml_entity_id || ''}
                                                onChange={(e) => setEditingProvider({ ...editingProvider, saml_entity_id: e.target.value })}
                                                required
                                                className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs px-5"
                                                placeholder="SAML Entity ID"
                                            />
                                        </div>
                                        <div className="space-y-4 md:col-span-2">
                                            <Label htmlFor="sso_url" className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1 italic">03 // Sso vector url</Label>
                                            <div className="relative">
                                                <Activity className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-on-surface-variant/40" />
                                                <Input
                                                    id="sso_url"
                                                    type="url"
                                                    value={editingProvider.saml_sso_url || ''}
                                                    onChange={(e) => setEditingProvider({ ...editingProvider, saml_sso_url: e.target.value })}
                                                    required
                                                    className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs pl-12"
                                                    placeholder="https://idp.saml.endpoint"
                                                />
                                            </div>
                                        </div>
                                        <div className="space-y-4 md:col-span-2">
                                            <Label htmlFor="cert" className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1 italic">04 // Pem certification logic</Label>
                                            <textarea
                                                id="cert"
                                                className="flex min-h-[200px] w-full border-none rounded-2xl bg-surface-container/50 ring-1 ring-on-surface/5 p-6 font-mono text-[11px] leading-relaxed focus:outline-none focus:ring-2 focus:ring-primary/20 custom-scrollbar-dark text-on-surface"
                                                value={editingProvider.saml_certificate || ''}
                                                onChange={(e) => setEditingProvider({ ...editingProvider, saml_certificate: e.target.value })}
                                                rows={8}
                                                placeholder="-----BEGIN CERTIFICATE-----..."
                                            />
                                        </div>

                                        <div className="flex flex-wrap gap-8 pt-4 md:col-span-2">
                                            <div className="flex items-center space-x-3 group cursor-pointer">
                                                <Switch
                                                    id="saml-sign-assertions"
                                                    checked={editingProvider.saml_sign_assertions ?? true}
                                                    onCheckedChange={checked => setEditingProvider({ ...editingProvider, saml_sign_assertions: checked })}
                                                    className="data-[state=checked]:bg-primary"
                                                />
                                                <Label htmlFor="saml-sign-assertions" className="flex items-center gap-2 cursor-pointer">
                                                    <ShieldCheck className="h-4 w-4 text-primary" />
                                                    <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/60 group-hover:text-on-surface transition-colors">Sign assertions</span>
                                                </Label>
                                            </div>
                                            <div className="flex items-center space-x-3 group cursor-pointer">
                                                <Switch
                                                    id="saml-encrypt-assertions"
                                                    checked={editingProvider.saml_encrypt_assertions ?? false}
                                                    onCheckedChange={checked => setEditingProvider({ ...editingProvider, saml_encrypt_assertions: checked })}
                                                    className="data-[state=checked]:bg-amber-500"
                                                />
                                                <Label htmlFor="saml-encrypt-assertions" className="flex items-center gap-2 cursor-pointer">
                                                    <Lock className="h-4 w-4 text-amber-500" />
                                                    <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/60 group-hover:text-on-surface transition-colors">Encrypt assertions</span>
                                                </Label>
                                            </div>
                                        </div>
                                    </>
                                )}
                            </div>

                            <div className="flex items-center space-x-5 p-6 rounded-2xl bg-primary/5 ring-1 ring-primary/10 border-none shadow-sm">
                                <Switch
                                    id="auto-create"
                                    checked={editingProvider.auto_create_users ?? true}
                                    onCheckedChange={(checked) => setEditingProvider({ ...editingProvider, auto_create_users: checked })}
                                    className="data-[state=checked]:bg-primary"
                                />
                                <div className="space-y-1">
                                    <Label htmlFor="auto-create" className="text-[12px] font-bold cursor-pointer leading-none text-on-surface">Auto-provision sync cells</Label>
                                    <p className="text-[10px] font-medium text-on-surface-variant/40 italic">Automatically instantiate user records upon successful federation handshake.</p>
                                </div>
                            </div>

                            <div className="flex justify-end gap-3 pt-6 border-t border-on-surface/5">
                                <Button
                                    type="button"
                                    variant="ghost"
                                    onClick={() => setEditingProvider(null)}
                                    className="h-9 px-6 rounded-lg font-bold text-[11px] tracking-tight text-on-surface-variant/40 hover:text-on-surface hover:bg-surface-container transition-all"
                                >
                                    Discard
                                </Button>
                                <Button
                                    type="submit"
                                    className="h-9 rounded-lg font-bold text-[11px] tracking-tight px-8 shadow-xl shadow-primary/20 transition-all"
                                >
                                    Save architecture
                                </Button>
                            </div>
                        </form>
                    </GlassCardContent>
                </GlassCard>
            )}
        </div>
    );
}
