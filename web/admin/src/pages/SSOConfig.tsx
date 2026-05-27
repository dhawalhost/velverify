import { useState, useEffect } from 'react';
import { getSSOProviders, createSSOProvider, updateSSOProvider, deleteSSOProvider, toggleSSOProvider } from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import {
    Plus,
    Trash2,
    Edit,
    ShieldCheck,
    Lock,
    Fingerprint,
    Activity,
    Terminal,
    X,
    Loader2,
    Building2,
    ChevronRight,
    Search,
    HelpCircle
} from 'lucide-react';
import {
    GlassCard,
    GlassCardHeader,
    GlassCardTitle,
    GlassCardContent,
    GlassCardDescription
} from '@/components/layout';
import { cn } from '@/lib/utils';

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
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedProvider, setSelectedProvider] = useState<Partial<SSOProvider> | null>(null);
    const [isCreating, setIsCreating] = useState(false);
    const [isEditing, setIsEditing] = useState(false);

    useEffect(() => {
        loadProviders();
    }, []);

    const loadProviders = async () => {
        try {
            setLoading(true);
            const res = await getSSOProviders();
            const loaded = res.providers || [];
            setProviders(loaded);
            
            // Proactively select the first provider if available and none selected yet
            if (loaded.length > 0 && !selectedProvider) {
                setSelectedProvider(loaded[0]);
                setIsCreating(false);
                setIsEditing(false);
            }
        } catch (error) {
            console.error('Failed to load providers:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleSave = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!selectedProvider) return;

        try {
            setLoading(true);
            if (isCreating) {
                await createSSOProvider(selectedProvider);
            } else if (selectedProvider.id) {
                await updateSSOProvider(selectedProvider.id, selectedProvider);
            }
            setIsCreating(false);
            setIsEditing(false);
            await loadProviders();
        } catch (error) {
            console.error('Failed to save provider:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (confirm('Are you sure you want to delete this provider?')) {
            try {
                setLoading(true);
                await deleteSSOProvider(id);
                if (selectedProvider?.id === id) {
                    setSelectedProvider(null);
                }
                await loadProviders();
            } catch (error) {
                console.error('Failed to delete provider:', error);
            } finally {
                setLoading(false);
            }
        }
    };

    const handleToggle = async (id: string, enabled: boolean) => {
        try {
            await toggleSSOProvider(id, enabled);
            // Refresh list
            const res = await getSSOProviders();
            const loaded = res.providers || [];
            setProviders(loaded);
            
            // Sync selected provider if it matches
            if (selectedProvider?.id === id) {
                setSelectedProvider(prev => prev ? { ...prev, enabled } : null);
            }
        } catch (error) {
            console.error('Failed to toggle provider:', error);
        }
    };

    const startCreate = (type: 'oidc' | 'saml') => {
        setSelectedProvider({
            type,
            enabled: true,
            auto_create_users: true,
            name: '',
            oidc_scopes: type === 'oidc' ? 'openid profile email' : undefined,
            saml_sign_assertions: type === 'saml' ? true : undefined,
            saml_encrypt_assertions: type === 'saml' ? false : undefined
        });
        setIsCreating(true);
        setIsEditing(true);
    };

    const selectProvider = (p: SSOProvider) => {
        setSelectedProvider(p);
        setIsCreating(false);
        setIsEditing(false);
    };

    const filteredProviders = providers.filter(p =>
        p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        p.type.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="flex h-full gap-0 animate-in fade-in duration-500">
            {/* ── Master: Provider List (Left Panel) ───────────────────────────────── */}
            <div className={cn(
                "flex flex-col transition-all duration-300 border-r border-on-surface/5 bg-card/10 h-full",
                selectedProvider ? "w-[380px] min-w-[380px]" : "flex-1"
            )}>
                {/* Toolbar */}
                <div className="flex flex-col gap-4 px-6 py-5 border-b border-on-surface/5 bg-card/40">
                    <div className="flex items-center justify-between">
                        <div>
                            <h1 className="text-sm font-bold tracking-tight text-on-surface">SSO Connectors</h1>
                            <p className="text-[10px] text-on-surface-variant/40 font-medium mt-0.5">
                                {providers.length} configured federation identity cells
                            </p>
                        </div>
                        <div className="flex items-center gap-1.5">
                            <Button
                                size="sm"
                                onClick={() => startCreate('oidc')}
                                className="h-7 rounded-lg bg-primary text-primary-foreground font-bold text-[9px] px-2.5 shadow-md shadow-primary/10"
                            >
                                <Plus className="w-3 h-3 mr-1" /> +OIDC
                            </Button>
                            <Button
                                size="sm"
                                variant="outline"
                                onClick={() => startCreate('saml')}
                                className="h-7 rounded-lg bg-card/50 ring-1 ring-on-surface/5 font-bold text-[9px] px-2.5 hover:bg-surface-container/60 text-on-surface"
                            >
                                <Plus className="w-3 h-3 mr-1" /> +SAML
                            </Button>
                        </div>
                    </div>

                    {/* Search bar */}
                    <div className="relative group">
                        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-on-surface-variant/30 group-focus-within:text-primary transition-colors" />
                        <Input
                            placeholder="Search federation..."
                            className="h-8 w-full border-none rounded-lg text-[11px] pl-8 bg-surface-container/40 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 font-medium"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                </div>

                {/* List Container */}
                <div className="flex-1 overflow-y-auto custom-scrollbar">
                    {loading && providers.length === 0 ? (
                        <div className="h-48 flex items-center justify-center">
                            <Loader2 className="h-6 w-6 animate-spin text-primary/30" />
                        </div>
                    ) : filteredProviders.length === 0 ? (
                        <div className="py-20 text-center text-[11px] text-on-surface-variant/20 italic font-medium">
                            No matching federation cells found
                        </div>
                    ) : (
                        <div className="divide-y divide-on-surface/5">
                            {filteredProviders.map((p) => {
                                const isSelected = selectedProvider?.id === p.id && !isCreating;
                                return (
                                    <div
                                        key={p.id}
                                        onClick={() => selectProvider(p)}
                                        className={cn(
                                            "flex items-center gap-3 px-5 py-4 cursor-pointer transition-all group border-l-2",
                                            isSelected
                                                ? "bg-primary/5 border-primary"
                                                : "hover:bg-surface-container/40 border-transparent"
                                        )}
                                    >
                                        <div className={cn(
                                            "w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ring-1 ring-on-surface/5",
                                            isSelected ? "bg-primary/10 text-primary" : "bg-surface-container/50 text-on-surface-variant/60"
                                        )}>
                                            <Building2 className="w-4 h-4" />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <p className={cn(
                                                "text-[12px] font-semibold truncate transition-colors",
                                                isSelected ? "text-primary" : "text-on-surface group-hover:text-primary"
                                            )}>
                                                {p.name}
                                            </p>
                                            <div className="flex items-center gap-2 mt-1">
                                                <Badge className={cn(
                                                    "text-[8px] font-bold px-1.5 py-0 rounded border-none uppercase shadow-none",
                                                    p.type === 'oidc' ? "bg-primary/10 text-primary" : "bg-amber-500/10 text-amber-500"
                                                )}>
                                                    {p.type}
                                                </Badge>
                                                <span className="text-[9px] text-on-surface-variant/20">•</span>
                                                <span className={cn(
                                                    "text-[9px] font-semibold",
                                                    p.enabled ? "text-success" : "text-on-surface-variant/30"
                                                )}>
                                                    {p.enabled ? 'Live' : 'Off'}
                                                </span>
                                            </div>
                                        </div>
                                        <ChevronRight className={cn(
                                            "w-3.5 h-3.5 transition-all shrink-0",
                                            isSelected ? "text-primary translate-x-0.5" : "text-on-surface-variant/20"
                                        )} />
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </div>

            {/* ── Detail Panel: Provider Details & Settings (Right Panel) ───────────────── */}
            <div className="flex-1 bg-card/20 flex flex-col h-full overflow-hidden">
                {selectedProvider ? (
                    <div className="flex-1 flex flex-col h-full overflow-hidden animate-in slide-in-from-right-4 duration-300">
                        {/* Header banner */}
                        <div className="bg-primary px-8 py-6 text-primary-foreground shrink-0 relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-8 opacity-10 rotate-12">
                                <Building2 className="w-32 h-32" />
                            </div>
                            <div className="relative z-10 flex items-start justify-between">
                                <div className="flex items-center gap-5">
                                    <div className="w-12 h-12 bg-black/10 rounded-xl flex items-center justify-center backdrop-blur-sm">
                                        <Building2 className="w-6 h-6 text-primary-foreground" />
                                    </div>
                                    <div>
                                        <h2 className="text-lg font-bold tracking-tight text-primary-foreground">
                                            {isCreating ? `New ${selectedProvider.type?.toUpperCase()} Federation` : selectedProvider.name}
                                        </h2>
                                        <div className="flex items-center gap-3 mt-1.5">
                                            <Badge className="bg-black/10 text-primary-foreground border-none text-[8px] font-bold tracking-wider px-2 uppercase shadow-none h-5">
                                                {selectedProvider.type}
                                            </Badge>
                                            <span className="text-primary-foreground/30">•</span>
                                            <div className="flex items-center gap-2">
                                                <Switch
                                                    checked={selectedProvider.enabled ?? false}
                                                    disabled={isCreating}
                                                    onCheckedChange={(checked) => handleToggle(selectedProvider.id!, checked)}
                                                    className="h-3.5 w-6 data-[state=checked]:bg-black/40"
                                                />
                                                <span className="text-[9px] font-bold text-primary-foreground/80 uppercase">
                                                    {selectedProvider.enabled ? 'Live' : 'Inactive'}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                {!isCreating && (
                                    <div className="flex items-center gap-2">
                                        <Button
                                            onClick={() => setIsEditing(!isEditing)}
                                            className="h-8 rounded-lg bg-black/10 hover:bg-black/20 text-primary-foreground font-semibold text-[10px] uppercase tracking-wide px-4 border-none shadow-none"
                                        >
                                            {isEditing ? 'View Mode' : 'Edit Configuration'}
                                        </Button>
                                        <Button
                                            onClick={() => handleDelete(selectedProvider.id!)}
                                            className="h-8 w-8 rounded-lg bg-black/10 hover:bg-red-500/20 text-primary-foreground hover:text-red-300 flex items-center justify-center p-0 border-none shadow-none"
                                        >
                                            <Trash2 className="w-4 h-4" />
                                        </Button>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Configuration Details Form / Viewer */}
                        <div className="flex-1 overflow-y-auto custom-scrollbar p-8 space-y-6">
                            {isEditing ? (
                                <form onSubmit={handleSave} className="space-y-6 max-w-3xl">
                                    <div className="space-y-2">
                                        <Label htmlFor="name" className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">01 // Identification alias</Label>
                                        <Input
                                            id="name"
                                            value={selectedProvider.name || ''}
                                            onChange={(e) => setSelectedProvider({ ...selectedProvider, name: e.target.value })}
                                            required
                                            className="h-10 border-none rounded-xl bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-medium px-4 text-sm"
                                            placeholder="e.g. Google Workspace OIDC"
                                        />
                                    </div>

                                    <div className="h-px bg-on-surface/5" />

                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        {selectedProvider.type === 'oidc' && (
                                            <>
                                                <div className="space-y-2 md:col-span-2">
                                                    <Label htmlFor="issuer" className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">02 // OIDC Issuer Discovery Endpoint</Label>
                                                    <div className="relative">
                                                        <Activity className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-on-surface-variant/40" />
                                                        <Input
                                                            id="issuer"
                                                            type="url"
                                                            value={selectedProvider.oidc_issuer_url || ''}
                                                            onChange={(e) => setSelectedProvider({ ...selectedProvider, oidc_issuer_url: e.target.value })}
                                                            required
                                                            className="h-10 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-[11px] pl-12"
                                                            placeholder="https://accounts.google.com"
                                                        />
                                                    </div>
                                                </div>
                                                <div className="space-y-2">
                                                    <Label htmlFor="client_id" className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">03 // Handshake Client ID</Label>
                                                    <Input
                                                        id="client_id"
                                                        value={selectedProvider.oidc_client_id || ''}
                                                        onChange={(e) => setSelectedProvider({ ...selectedProvider, oidc_client_id: e.target.value })}
                                                        required
                                                        className="h-10 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-[11px] px-4"
                                                        placeholder="OIDC Client ID"
                                                    />
                                                </div>
                                                <div className="space-y-2">
                                                    <Label htmlFor="client_secret" className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">04 // Secret Entropy {isCreating ? '' : '(locked)'}</Label>
                                                    <Input
                                                        id="client_secret"
                                                        type="password"
                                                        value={selectedProvider.oidc_client_secret || ''}
                                                        onChange={(e) => setSelectedProvider({ ...selectedProvider, oidc_client_secret: e.target.value })}
                                                        required={isCreating}
                                                        className="h-10 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all text-xs px-4"
                                                        placeholder={isCreating ? "OIDC Client Secret" : "••••••••••••••••"}
                                                    />
                                                </div>
                                                <div className="space-y-2 md:col-span-2">
                                                    <Label htmlFor="scopes" className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">05 // Claim Scopes</Label>
                                                    <Input
                                                        id="scopes"
                                                        value={selectedProvider.oidc_scopes || 'openid profile email'}
                                                        onChange={(e) => setSelectedProvider({ ...selectedProvider, oidc_scopes: e.target.value })}
                                                        className="h-10 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-[11px] px-4"
                                                    />
                                                </div>
                                            </>
                                        )}

                                        {selectedProvider.type === 'saml' && (
                                            <>
                                                <div className="space-y-2 md:col-span-2">
                                                    <Label htmlFor="entity_id" className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">02 // SAML Audience Subject Identifier (Entity ID)</Label>
                                                    <Input
                                                        id="entity_id"
                                                        value={selectedProvider.saml_entity_id || ''}
                                                        onChange={(e) => setSelectedProvider({ ...selectedProvider, saml_entity_id: e.target.value })}
                                                        required
                                                        className="h-10 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-[11px] px-4"
                                                        placeholder="SAML Entity ID"
                                                    />
                                                </div>
                                                <div className="space-y-2 md:col-span-2">
                                                    <Label htmlFor="sso_url" className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">03 // SAML SSO Vector Endpoint URL</Label>
                                                    <div className="relative">
                                                        <Activity className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-on-surface-variant/40" />
                                                        <Input
                                                            id="sso_url"
                                                            type="url"
                                                            value={selectedProvider.saml_sso_url || ''}
                                                            onChange={(e) => setSelectedProvider({ ...selectedProvider, saml_sso_url: e.target.value })}
                                                            required
                                                            className="h-10 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-[11px] pl-12"
                                                            placeholder="https://idp.okta.com/app/sso"
                                                        />
                                                    </div>
                                                </div>
                                                <div className="space-y-2 md:col-span-2">
                                                    <Label htmlFor="cert" className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">04 // PEM Signature Certification Logic</Label>
                                                    <textarea
                                                        id="cert"
                                                        className="flex min-h-[160px] w-full border-none rounded-xl bg-surface-container/50 ring-1 ring-on-surface/5 p-4 font-mono text-[10px] leading-relaxed focus:outline-none focus:ring-2 focus:ring-primary/20 custom-scrollbar text-on-surface"
                                                        value={selectedProvider.saml_certificate || ''}
                                                        onChange={(e) => setSelectedProvider({ ...selectedProvider, saml_certificate: e.target.value })}
                                                        rows={6}
                                                        placeholder="-----BEGIN CERTIFICATE-----&#10;..."
                                                    />
                                                </div>

                                                <div className="flex flex-wrap gap-6 pt-2 md:col-span-2">
                                                    <div className="flex items-center space-x-2.5 group cursor-pointer">
                                                        <Switch
                                                            id="saml-sign-assertions"
                                                            checked={selectedProvider.saml_sign_assertions ?? true}
                                                            onCheckedChange={checked => setSelectedProvider({ ...selectedProvider, saml_sign_assertions: checked })}
                                                            className="h-4 w-7 data-[state=checked]:bg-primary"
                                                        />
                                                        <Label htmlFor="saml-sign-assertions" className="flex items-center gap-1.5 cursor-pointer">
                                                            <ShieldCheck className="h-3.5 w-3.5 text-primary" />
                                                            <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/60 group-hover:text-on-surface transition-colors">Sign assertions</span>
                                                        </Label>
                                                    </div>
                                                    <div className="flex items-center space-x-2.5 group cursor-pointer">
                                                        <Switch
                                                            id="saml-encrypt-assertions"
                                                            checked={selectedProvider.saml_encrypt_assertions ?? false}
                                                            onCheckedChange={checked => setSelectedProvider({ ...selectedProvider, saml_encrypt_assertions: checked })}
                                                            className="h-4 w-7 data-[state=checked]:bg-amber-500"
                                                        />
                                                        <Label htmlFor="saml-encrypt-assertions" className="flex items-center gap-1.5 cursor-pointer">
                                                            <Lock className="h-3.5 w-3.5 text-amber-500" />
                                                            <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/60 group-hover:text-on-surface transition-colors">Encrypt assertions</span>
                                                        </Label>
                                                    </div>
                                                </div>
                                            </>
                                        )}
                                    </div>

                                    <div className="flex items-center space-x-4 p-4 rounded-xl bg-primary/5 ring-1 ring-primary/10 border-none shadow-none">
                                        <Switch
                                            id="auto-create"
                                            checked={selectedProvider.auto_create_users ?? true}
                                            onCheckedChange={(checked) => setSelectedProvider({ ...selectedProvider, auto_create_users: checked })}
                                            className="h-4 w-7 data-[state=checked]:bg-primary"
                                        />
                                        <div className="space-y-0.5">
                                            <Label htmlFor="auto-create" className="text-[11px] font-bold cursor-pointer text-on-surface">Auto-provision Sync Cells</Label>
                                            <p className="text-[9px] text-on-surface-variant/40">Automatically instantiate dynamic user identities upon successful federation lookup.</p>
                                        </div>
                                    </div>

                                    <div className="flex justify-end gap-3 pt-4 border-t border-on-surface/5">
                                        <Button
                                            type="button"
                                            variant="ghost"
                                            onClick={() => {
                                                setIsEditing(false);
                                                if (isCreating) setSelectedProvider(providers[0] || null);
                                                setIsCreating(false);
                                            }}
                                            className="h-9 px-5 rounded-lg font-bold text-[10px] uppercase tracking-wide text-on-surface-variant/40 hover:text-on-surface hover:bg-surface-container"
                                        >
                                            Cancel
                                        </Button>
                                        <Button
                                            type="submit"
                                            className="h-9 rounded-lg font-bold text-[10px] uppercase tracking-wide px-6 shadow-lg shadow-primary/25"
                                        >
                                            Save Architecture
                                        </Button>
                                    </div>
                                </form>
                            ) : (
                                <div className="space-y-8 max-w-4xl">
                                    {/* Overview Metadata Section */}
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                        <GlassCard className="border-none shadow-lg shadow-on-surface/5 bg-card rounded-xl">
                                            <GlassCardContent className="p-5 flex flex-col gap-1.5">
                                                <span className="text-[10px] font-bold text-on-surface-variant/40 uppercase">Federation Type</span>
                                                <span className="text-lg font-bold text-on-surface uppercase">{selectedProvider.type}</span>
                                            </GlassCardContent>
                                        </GlassCard>
                                        <GlassCard className="border-none shadow-lg shadow-on-surface/5 bg-card rounded-xl">
                                            <GlassCardContent className="p-5 flex flex-col gap-1.5">
                                                <span className="text-[10px] font-bold text-on-surface-variant/40 uppercase">Handshake Provisioning</span>
                                                <span className="text-lg font-bold text-on-surface">{selectedProvider.auto_create_users ? 'Auto-Sync' : 'Explicit-Only'}</span>
                                            </GlassCardContent>
                                        </GlassCard>
                                        <GlassCard className="border-none shadow-lg shadow-on-surface/5 bg-card rounded-xl">
                                            <GlassCardContent className="p-5 flex flex-col gap-1.5">
                                                <span className="text-[10px] font-bold text-on-surface-variant/40 uppercase">Tunnel Health State</span>
                                                <span className={cn(
                                                    "text-lg font-bold",
                                                    selectedProvider.enabled ? "text-success" : "text-on-surface-variant/30"
                                                )}>
                                                    {selectedProvider.enabled ? 'ONLINE' : 'OFFLINE'}
                                                </span>
                                            </GlassCardContent>
                                        </GlassCard>
                                    </div>

                                    {/* Parameters List */}
                                    <div className="space-y-4">
                                        <h3 className="text-[10px] font-bold tracking-wider text-on-surface-variant/40 uppercase italic">SSO Configuration Matrix</h3>
                                        <GlassCard className="border-none shadow-xl bg-card rounded-xl divide-y divide-on-surface/5">
                                            {selectedProvider.type === 'oidc' ? (
                                                <>
                                                    <div className="p-5 flex flex-col gap-2">
                                                        <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 uppercase">OIDC Discovery Issuer Url</span>
                                                        <span className="font-mono text-[11px] text-primary truncate">{selectedProvider.oidc_issuer_url}</span>
                                                    </div>
                                                    <div className="p-5 flex flex-col gap-2">
                                                        <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Client ID Primitives</span>
                                                        <span className="font-mono text-[11px] text-on-surface truncate">{selectedProvider.oidc_client_id}</span>
                                                    </div>
                                                    <div className="p-5 flex flex-col gap-2">
                                                        <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Authorized Sync Scopes</span>
                                                        <span className="font-mono text-[11px] text-on-surface-variant">{selectedProvider.oidc_scopes}</span>
                                                    </div>
                                                </>
                                            ) : (
                                                <>
                                                    <div className="p-5 flex flex-col gap-2">
                                                        <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 uppercase">SAML Audience Entity ID</span>
                                                        <span className="font-mono text-[11px] text-on-surface truncate">{selectedProvider.saml_entity_id}</span>
                                                    </div>
                                                    <div className="p-5 flex flex-col gap-2">
                                                        <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 uppercase">SAML SSO Vector Endpoint</span>
                                                        <span className="font-mono text-[11px] text-primary truncate">{selectedProvider.saml_sso_url}</span>
                                                    </div>
                                                    <div className="p-5 flex flex-col gap-2">
                                                        <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Cryptographic Options</span>
                                                        <div className="flex gap-4 mt-1">
                                                            <Badge className="bg-primary/5 text-primary border border-primary/10 shadow-none text-[8px] uppercase font-bold">
                                                                Sign assertions: {selectedProvider.saml_sign_assertions ? 'Yes' : 'No'}
                                                            </Badge>
                                                            <Badge className="bg-amber-500/5 text-amber-500 border border-amber-500/10 shadow-none text-[8px] uppercase font-bold">
                                                                Encrypt assertions: {selectedProvider.saml_encrypt_assertions ? 'Yes' : 'No'}
                                                            </Badge>
                                                        </div>
                                                    </div>
                                                    {selectedProvider.saml_certificate && (
                                                        <div className="p-5 flex flex-col gap-2">
                                                            <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Sign Certification PEM block</span>
                                                            <pre className="p-4 rounded-lg bg-surface-container/30 text-[10px] font-mono leading-relaxed overflow-x-auto text-on-surface-variant/80 max-h-48 custom-scrollbar">
                                                                {selectedProvider.saml_certificate}
                                                            </pre>
                                                        </div>
                                                    )}
                                                </>
                                            )}
                                        </GlassCard>
                                    </div>

                                    {/* Dynamic Integration Guides */}
                                    <div className="p-6 rounded-xl bg-surface-container/30 border border-on-surface/5 flex gap-4">
                                        <div className="p-2.5 bg-primary/5 text-primary rounded-lg self-start">
                                            <HelpCircle className="w-5 h-5" />
                                        </div>
                                        <div className="space-y-2">
                                            <h4 className="text-[12px] font-bold tracking-tight text-on-surface">Integrating with your Identity Provider</h4>
                                            <p className="text-[10px] text-on-surface-variant/60 leading-relaxed max-w-2xl font-medium">
                                                To successfully establish single sign-on, you must configure this platform as an authorized application in your identity provider dashboard (e.g. Okta, Auth0, Microsoft Entra ID). Set your provider redirect or ACS URL endpoints to point to your tenant slug gateway.
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                ) : (
                    <div className="flex-1 flex flex-col items-center justify-center text-center text-on-surface-variant/20 italic p-8">
                        <div className="w-20 h-20 bg-surface-container/40 rounded-3xl flex items-center justify-center mb-6">
                            <Building2 className="w-10 h-10 opacity-30 text-on-surface-variant" />
                        </div>
                        <h3 className="text-base font-bold text-on-surface-variant/30 not-italic uppercase tracking-wider mb-2">No selected provider</h3>
                        <p className="text-[11px] font-medium max-w-xs leading-relaxed opacity-60">Select an existing federation identity cell or integrate a new tunnel from the master list.</p>
                    </div>
                )}
            </div>
        </div>
    );
}
