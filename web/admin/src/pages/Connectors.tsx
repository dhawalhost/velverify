import React, { useState, useEffect } from 'react';
import { getConnectors, createConnector, updateConnector, deleteConnector, toggleConnector, testConnector } from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Loader2, Plus, Plug, Trash2, Check, X, Settings, ArrowLeft, RotateCcw, Link2, ExternalLink, ShieldCheck, Terminal, Fingerprint, Database } from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassCardDescription } from '@/components/layout';

interface ConnectorConfig {
    id: string;
    name: string;
    type: string;
    enabled: boolean;
    endpoint: string;
    credentials: Record<string, string>;
    settings: Record<string, string>;
}

export default function Connectors() {
    const [connectors, setConnectors] = useState<ConnectorConfig[]>([]);
    const [loading, setLoading] = useState(true);
    const [editingConnector, setEditingConnector] = useState<Partial<ConnectorConfig> | null>(null);
    const [isCreating, setIsCreating] = useState(false);
    const [testResult, setTestResult] = useState<{ status: string; error?: string } | null>(null);
    const [testing, setTesting] = useState(false);

    useEffect(() => { loadConnectors(); }, []);

    const loadConnectors = async () => {
        try {
            const res = await getConnectors();
            setConnectors(res.connectors || []);
        } catch (error) {
            console.error('Failed to load connectors:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleSave = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!editingConnector) return;

        try {
            if (isCreating) {
                await createConnector(editingConnector);
            } else if (editingConnector.id) {
                await updateConnector(editingConnector.id, editingConnector);
            }
            setEditingConnector(null);
            setIsCreating(false);
            setTestResult(null);
            loadConnectors();
        } catch (error) {
            console.error('Failed to save connector:', error);
            alert('Failed to save: ' + (error as any).message);
        }
    };

    const handleDelete = async (id: string) => {
        if (confirm('Are you sure you want to delete this connector?')) {
            try {
                await deleteConnector(id);
                loadConnectors();
            } catch (error) {
                console.error('Failed to delete connector:', error);
            }
        }
    };

    const handleToggle = async (id: string, enabled: boolean) => {
        try {
            await toggleConnector(id, enabled);
            loadConnectors();
        } catch (error) {
            console.error('Failed to toggle connector:', error);
        }
    };

    const handleTest = async () => {
        if (!editingConnector) return;
        setTesting(true);
        setTestResult(null);
        try {
            await testConnector(editingConnector);
            setTestResult({ status: 'success' });
        } catch (error: any) {
            console.error('Test failed:', error);
            setTestResult({ status: 'failed', error: error.response?.data?.error || error.message });
        } finally {
            setTesting(false);
        }
    };

    const updateNested = (field: 'credentials' | 'settings', key: string, value: string) => {
        if (!editingConnector) return;
        setEditingConnector({
            ...editingConnector,
            [field]: { ...(editingConnector[field] || {}), [key]: value }
        });
    };

    if (loading && connectors.length === 0) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    if (editingConnector) {
        return (
            <div className="space-y-12 animate-in fade-in duration-700">
                <PageHeader
                    icon={<Plug className="w-8 h-8 text-primary" />}
                    title={isCreating ? 'Add Connector' : 'Edit Connector'}
                    description={`Configure how WardSeal syncs data with your external provider.`}
                    actions={
                        <Button
                            variant="outline"
                            onClick={() => { setEditingConnector(null); setTestResult(null); }}
                            className="bg-card rounded-lg font-bold tracking-tight text-[10px] h-9 px-6 ring-1 ring-on-surface/5 shadow-sm hover:bg-surface-container transition-all"
                        >
                            <ArrowLeft className="mr-2 h-3.5 w-3.5" /> Cancel
                        </Button>
                    }
                />

                <div className="flex justify-center">
                    <GlassCard className="w-full max-w-4xl border-none shadow-xl shadow-on-surface/10 bg-card overflow-hidden rounded-xl">
                        <GlassCardHeader className="py-6 px-6 border-b border-on-surface/5 bg-surface-container/10">
                            <div className="flex items-center gap-4">
                                <div className="p-3 bg-primary rounded-xl text-white shadow-lg shadow-primary/20">
                                    <ExternalLink className="w-5 h-5" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">
                                        {editingConnector.type ? editingConnector.type.charAt(0).toUpperCase() + editingConnector.type.slice(1).toLowerCase() : 'Generic'} Connector
                                    </GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-bold text-[10px] mt-0.5 tracking-tight">Sync users and groups from your external directory.</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-6 space-y-6">
                            <form onSubmit={handleSave} className="space-y-6">
                                <div className="space-y-2">
                                    <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1">01 // Connection Name</Label>
                                    <Input
                                        placeholder="e.g., Corporate LDAP"
                                        value={editingConnector.name || ''}
                                        onChange={(e) => setEditingConnector({ ...editingConnector, name: e.target.value })}
                                        required
                                        className="h-10 border-none rounded-lg bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-medium px-4 text-sm"
                                    />
                                </div>

                                <div className="h-px bg-on-surface/5" />

                                {/* DYNAMIC FORM CONTENT */}
                                <div className="space-y-6">
                                    <div className="flex items-center gap-2">
                                        <div className="h-1 w-1 rounded-full bg-primary" />
                                        <h3 className="text-[10px] font-bold tracking-tight text-on-surface-variant/40">Connection Credentials</h3>
                                    </div>

                                    {editingConnector.type === 'scim' && (
                                        <div className="grid gap-6">
                                            <div className="space-y-2">
                                                <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Endpoint Protocol</Label>
                                                <Input
                                                    type="url"
                                                    placeholder="https://scim.identity.provider/v2"
                                                    value={editingConnector.endpoint || ''}
                                                    onChange={(e) => setEditingConnector({ ...editingConnector, endpoint: e.target.value })}
                                                    required
                                                    className="h-10 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs px-4"
                                                />
                                            </div>
                                            <div className="space-y-2">
                                                <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Bearer Token</Label>
                                                <Input
                                                    type="password"
                                                    placeholder="••••••••••••••••"
                                                    value={editingConnector.credentials?.token || ''}
                                                    onChange={(e) => updateNested('credentials', 'token', e.target.value)}
                                                    required={isCreating}
                                                    className="h-10 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all text-xs px-4"
                                                />
                                            </div>
                                        </div>
                                    )}

                                    {editingConnector.type === 'ldap' && (
                                        <div className="grid gap-6">
                                            <div className="space-y-3">
                                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Server URL</Label>
                                                <Input
                                                    placeholder="ldaps://identity.corp:636"
                                                    value={editingConnector.endpoint || ''}
                                                    onChange={(e) => setEditingConnector({ ...editingConnector, endpoint: e.target.value })}
                                                    required
                                                    className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs px-5"
                                                />
                                            </div>
                                            <div className="grid md:grid-cols-2 gap-6">
                                                <div className="space-y-3">
                                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Bind DN</Label>
                                                    <Input
                                                        placeholder="cn=admin,dc=corp,dc=com"
                                                        value={editingConnector.credentials?.bind_dn || ''}
                                                        onChange={(e) => updateNested('credentials', 'bind_dn', e.target.value)}
                                                        required
                                                        className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs px-5"
                                                    />
                                                </div>
                                                <div className="space-y-3">
                                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Bind Secret</Label>
                                                    <Input
                                                        type="password"
                                                        placeholder="••••••••"
                                                        value={editingConnector.credentials?.bind_password || ''}
                                                        onChange={(e) => updateNested('credentials', 'bind_password', e.target.value)}
                                                        required={isCreating}
                                                        className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all text-xs px-5"
                                                    />
                                                </div>
                                            </div>
                                            <div className="space-y-3">
                                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Hierarchy Root (Base DN)</Label>
                                                <Input
                                                    placeholder="dc=corp,dc=com"
                                                    value={editingConnector.settings?.base_dn || ''}
                                                    onChange={(e) => updateNested('settings', 'base_dn', e.target.value)}
                                                    required
                                                    className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs px-5"
                                                />
                                            </div>
                                        </div>
                                    )}

                                    {editingConnector.type === 'azure-ad' && (
                                        <div className="grid gap-6">
                                            <div className="p-5 rounded-2xl bg-primary/5 text-primary border border-primary/10 flex items-start gap-4 text-[11px] font-medium leading-relaxed shadow-sm">
                                                <ShieldCheck className="w-5 h-5 flex-shrink-0 mt-0.5" />
                                                This connection uses Microsoft Graph API. Ensure the App Registration has directory.read.all permissions in Entra ID.
                                            </div>
                                            <div className="space-y-3">
                                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Tenant ID</Label>
                                                <Input
                                                    placeholder="00000000-0000-0000-0000-000000000000"
                                                    value={editingConnector.credentials?.tenant_id || ''}
                                                    onChange={(e) => updateNested('credentials', 'tenant_id', e.target.value)}
                                                    required
                                                    className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs px-5"
                                                />
                                            </div>
                                            <div className="grid md:grid-cols-2 gap-6">
                                                <div className="space-y-3">
                                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Client ID</Label>
                                                    <Input
                                                        placeholder="00000000-0000-0000-0000-000000000000"
                                                        value={editingConnector.credentials?.client_id || ''}
                                                        onChange={(e) => updateNested('credentials', 'client_id', e.target.value)}
                                                        required
                                                        className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs px-5"
                                                    />
                                                </div>
                                                <div className="space-y-3">
                                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Client Secret</Label>
                                                    <Input
                                                        type="password"
                                                        placeholder="••••••••"
                                                        value={editingConnector.credentials?.client_secret || ''}
                                                        onChange={(e) => updateNested('credentials', 'client_secret', e.target.value)}
                                                        required={isCreating}
                                                        className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all text-xs px-5"
                                                    />
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {editingConnector.type === 'google' && (
                                        <div className="grid gap-6">
                                            <div className="grid md:grid-cols-2 gap-6">
                                                <div className="space-y-3">
                                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Workspace Domain</Label>
                                                    <Input
                                                        placeholder="acme.com"
                                                        value={editingConnector.settings?.domain || ''}
                                                        onChange={(e) => updateNested('settings', 'domain', e.target.value)}
                                                        required
                                                        className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all text-xs px-5"
                                                    />
                                                </div>
                                                <div className="space-y-3">
                                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Admin Email</Label>
                                                    <Input
                                                        type="email"
                                                        placeholder="admin@acme.com"
                                                        value={editingConnector.credentials?.admin_email || ''}
                                                        onChange={(e) => updateNested('credentials', 'admin_email', e.target.value)}
                                                        required
                                                        className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all text-xs px-5"
                                                    />
                                                </div>
                                            </div>
                                            <div className="space-y-2">
                                                <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Service Account Key (JSON)</Label>
                                                <textarea
                                                    className="flex min-h-[150px] w-full border-none rounded-xl bg-surface-container/50 ring-1 ring-on-surface/5 p-4 font-mono text-[10px] leading-relaxed focus:outline-none focus:ring-2 focus:ring-primary/20 custom-scrollbar-dark text-on-surface"
                                                    placeholder='{ "type": "service_account", ... }'
                                                    value={editingConnector.credentials?.service_account_json || ''}
                                                    onChange={(e) => updateNested('credentials', 'service_account_json', e.target.value)}
                                                    required={isCreating}
                                                />
                                            </div>
                                        </div>
                                    )}
                                </div>

                                <div className="h-px bg-on-surface/5" />

                                <div className="flex flex-col md:flex-row items-center gap-6">
                                    <Button
                                        type="button"
                                        variant="outline"
                                        onClick={handleTest}
                                        disabled={testing}
                                        className="h-10 w-full md:w-auto px-6 rounded-lg bg-card ring-1 ring-on-surface/5 font-bold tracking-tight text-[10px] transition-all hover:bg-primary/5 hover:text-primary hover:ring-primary/20"
                                    >
                                        {testing ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <RotateCcw className="mr-1.5 h-3.5 w-3.5" />}
                                        Test Connectivity
                                    </Button>

                                    {testResult && (
                                        <div className={`p-3 rounded-lg border flex items-center gap-3 animate-in slide-in-from-left-4 duration-500 flex-1 ${testResult.status === 'success' ? 'bg-success-subtle border-success/10 text-success' : 'bg-destructive/10 border-destructive/20 text-destructive'}`}>
                                            {testResult.status === 'success' ? <Check className="h-4 w-4" /> : <X className="h-4 w-4" />}
                                            <div className="flex flex-col">
                                                <span className="text-[10px] font-bold tracking-tight leading-none">{testResult.status === 'success' ? 'Test successful' : 'Test failed'}</span>
                                                {testResult.error && <span className="text-[9px] font-medium opacity-60 mt-1 truncate max-w-md">{testResult.error}</span>}
                                            </div>
                                        </div>
                                    )}
                                </div>

                                <div className="flex justify-end gap-3 pt-6 border-t border-on-surface/5">
                                    <Button
                                        type="button"
                                        variant="ghost"
                                        onClick={() => setEditingConnector(null)}
                                        className="h-10 px-6 rounded-lg font-bold text-[10px] tracking-tight text-on-surface-variant/40 hover:text-on-surface hover:bg-surface-container transition-all"
                                    >
                                        Discard
                                    </Button>
                                    <Button
                                        type="submit"
                                        className="h-10 rounded-lg font-bold text-[10px] tracking-tight px-8 shadow-lg shadow-primary/20 transition-all"
                                    >
                                        Save Configuration
                                    </Button>
                                </div>
                            </form>
                        </GlassCardContent>
                    </GlassCard>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-12 animate-in fade-in duration-700">
            <PageHeader
                icon={<Plug className="w-8 h-8 text-primary" />}
                title="External Sync"
                description="Connect your identity providers to sync users automatically."
            />

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <Button
                    variant="outline"
                    className="h-32 flex flex-col gap-3 items-center justify-center border-none bg-card hover:bg-primary/5 rounded-xl group transition-all relative overflow-hidden shadow-lg shadow-on-surface/5"
                    onClick={() => { setEditingConnector({ type: 'scim', enabled: true, credentials: {}, settings: {} }); setIsCreating(true); }}
                >
                    <div className="absolute top-0 right-0 p-3 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                        <Link2 className="w-16 h-16 -mr-3 -mt-3 text-primary" />
                    </div>
                    <div className="p-3 bg-primary/5 rounded-xl group-hover:bg-primary group-hover:text-primary-foreground transition-all text-primary">
                        <Plug className="h-6 w-6" />
                    </div>
                    <div className="flex flex-col items-center gap-1">
                        <span className="text-xs font-bold tracking-tight text-on-surface">Add SCIM</span>
                        <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/20 italic">Standard API Sync</span>
                    </div>
                </Button>

                <Button
                    variant="outline"
                    className="h-32 flex flex-col gap-3 items-center justify-center border-none bg-card hover:bg-primary/5 rounded-xl group transition-all relative overflow-hidden shadow-lg shadow-on-surface/5"
                    onClick={() => { setEditingConnector({ type: 'ldap', enabled: true, credentials: {}, settings: {} }); setIsCreating(true); }}
                >
                    <div className="absolute top-0 right-0 p-3 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                        <Database className="w-16 h-16 -mr-3 -mt-3 text-primary" />
                    </div>
                    <div className="p-3 bg-primary/5 rounded-xl group-hover:bg-primary group-hover:text-primary-foreground transition-all text-primary">
                        <span className="font-bold italic text-base leading-none">LDAP</span>
                    </div>
                    <div className="flex flex-col items-center gap-1">
                        <span className="text-xs font-bold tracking-tight text-on-surface">Add LDAP</span>
                        <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/20 italic">On-premise Sync</span>
                    </div>
                </Button>

                <Button
                    variant="outline"
                    className="h-32 flex flex-col gap-3 items-center justify-center border-none bg-card hover:bg-primary/5 rounded-xl group transition-all relative overflow-hidden shadow-lg shadow-on-surface/5"
                    onClick={() => { setEditingConnector({ type: 'azure-ad', enabled: true, credentials: {}, settings: {} }); setIsCreating(true); }}
                >
                    <div className="absolute top-0 right-0 p-3 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                        <ShieldCheck className="w-16 h-16 -mr-3 -mt-3 text-primary" />
                    </div>
                    <div className="p-3 bg-primary/5 rounded-xl group-hover:bg-primary group-hover:text-primary-foreground transition-all text-primary">
                        <span className="font-bold italic text-base leading-none">ENTRA</span>
                    </div>
                    <div className="flex flex-col items-center gap-1">
                        <span className="text-xs font-bold tracking-tight text-on-surface">Add Entra ID</span>
                        <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/20 italic">Microsoft Cloud Sync</span>
                    </div>
                </Button>

                <Button
                    variant="outline"
                    className="h-32 flex flex-col gap-3 items-center justify-center border-none bg-card hover:bg-primary/5 rounded-xl group transition-all relative overflow-hidden shadow-lg shadow-on-surface/5"
                    onClick={() => { setEditingConnector({ type: 'google', enabled: true, credentials: {}, settings: { domain: '' } }); setIsCreating(true); }}
                >
                    <div className="absolute top-0 right-0 p-3 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                        <Fingerprint className="w-16 h-16 -mr-3 -mt-3 text-primary" />
                    </div>
                    <div className="p-3 bg-primary/5 rounded-xl group-hover:bg-primary group-hover:text-primary-foreground transition-all text-primary">
                        <span className="font-bold italic text-base leading-none">GOOGLE</span>
                    </div>
                    <div className="flex flex-col items-center gap-1">
                        <span className="text-xs font-bold tracking-tight text-on-surface">Add Google</span>
                        <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/20 italic">Google Workspace Sync</span>
                    </div>
                </Button>
            </div>

            <div className="space-y-6">
                <div className="flex items-center gap-4">
                    <h2 className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 italic flex-shrink-0 uppercase">Active Sync Sources</h2>
                    <div className="h-px flex-1 bg-on-surface/5" />
                </div>

                <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                    <GlassCardHeader className="py-5 px-6 border-b border-on-surface/5">
                        <div className="flex items-center gap-4">
                            <div className="p-2.5 bg-primary/5 rounded-xl">
                                <Link2 className="w-5 h-5 text-primary" />
                            </div>
                            <div>
                                <GlassCardTitle className="text-lg font-bold tracking-tight text-on-surface">Configured Sources ({connectors.length})</GlassCardTitle>
                                <p className="text-on-surface-variant/20 font-bold text-[10px] mt-0.5 tracking-tight">Identify sources that are correctly syncing with WardSeal.</p>
                            </div>
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="p-0">
                        {connectors.length === 0 ? (
                            <div className="py-32 text-center text-sm font-medium text-on-surface-variant/30 italic">No sync sources configured.</div>
                        ) : (
                            <div className="divide-y divide-on-surface/5">
                                {connectors.map(c => (
                                    <div key={c.id} className="p-5 flex flex-col md:flex-row items-start md:items-center justify-between hover:bg-surface-container/10 transition-all group gap-6">
                                        <div className="flex items-center gap-5">
                                            <div className="w-10 h-10 rounded-xl bg-surface-container/50 text-on-surface-variant/40 flex items-center justify-center transition-all group-hover:bg-primary group-hover:text-primary-foreground group-hover:scale-105">
                                                <Plug className="h-4 w-4" />
                                            </div>
                                            <div className="flex flex-col gap-1">
                                                <div className="flex items-center gap-3">
                                                    <span className="text-base font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{c.name}</span>
                                                    <Badge className="bg-surface-container/50 text-on-surface-variant/40 border-none rounded font-bold text-[9px] tracking-tight px-2 py-0.5 group-hover:bg-primary/10 group-hover:text-primary transition-all">{c.type}</Badge>
                                                </div>
                                                <div className="flex items-center gap-2 text-[10px] font-bold tracking-tight text-on-surface-variant/20 group-hover:text-on-surface-variant/40 transition-opacity">
                                                    <Terminal className="h-2.5 w-2.5" />
                                                    Source: {c.endpoint || 'Internal'}
                                                </div>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-6 w-full md:w-auto mt-2 md:mt-0 pt-4 md:pt-0 border-t md:border-0 border-on-surface/5">
                                            <div className="flex items-center gap-4 px-4 py-2 rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5">
                                                <Switch
                                                    checked={c.enabled}
                                                    onCheckedChange={(checked) => handleToggle(c.id, checked)}
                                                    className="data-[state=checked]:bg-success"
                                                />
                                                <div className="flex flex-col">
                                                    <span className={`text-[10px] font-bold tracking-tight transition-all ${c.enabled ? 'text-success' : 'text-on-surface-variant/20'}`}>
                                                        {c.enabled ? 'Active' : 'Disabled'}
                                                    </span>
                                                    <span className="text-[8px] font-bold tracking-tight opacity-20 italic">Status</span>
                                                </div>
                                            </div>

                                            <div className="flex gap-1.5">
                                                <Button size="icon" variant="ghost" className="h-9 w-9 rounded-lg text-on-surface-variant/40 hover:text-on-surface hover:bg-surface-container transition-all" onClick={() => { setEditingConnector(c); setIsCreating(false); }}>
                                                    <Settings className="h-4 w-4" />
                                                </Button>
                                                <Button size="icon" variant="ghost" className="h-9 w-9 rounded-lg text-on-surface-variant/40 hover:text-destructive hover:bg-destructive/10 transition-all" onClick={() => handleDelete(c.id)}>
                                                    <Trash2 className="h-4 w-4" />
                                                </Button>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </GlassCardContent>
                </GlassCard>
            </div>
        </div>
    );
}
