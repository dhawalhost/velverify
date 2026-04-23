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
                    icon={<Plug className="w-10 h-10 text-primary" />}
                    title={isCreating ? 'Provision Connector' : 'Configure Vector'}
                    description={`Orchestrating bridge protocols for external identity shards. Synchronizing with the ${editingConnector.type?.toUpperCase()} matrix.`}
                    actions={
                        <Button
                            variant="outline"
                            onClick={() => { setEditingConnector(null); setTestResult(null); }}
                            className="bg-white rounded-xl font-bold tracking-tight text-[11px] h-11 px-8 ring-1 ring-on-surface/5 shadow-sm hover:bg-surface-container transition-all"
                        >
                            <ArrowLeft className="mr-2 h-4 w-4" /> Cancel
                        </Button>
                    }
                />

                <div className="flex justify-center">
                    <GlassCard className="w-full max-w-4xl border-none shadow-2xl shadow-on-surface/10 bg-white overflow-hidden rounded-[32px]">
                        <GlassCardHeader className="py-12 px-10 border-b border-on-surface/5 bg-surface-container/10">
                            <div className="flex items-center gap-6">
                                <div className="p-4 bg-primary rounded-2xl text-white shadow-lg shadow-primary/20">
                                    <ExternalLink className="w-7 h-7" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface">
                                        {editingConnector.type ? editingConnector.type.charAt(0).toUpperCase() + editingConnector.type.slice(1).toLowerCase() : 'Generic'} Integrator
                                    </GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-bold text-[12px] mt-1 tracking-tight">Architectural deep-link for enterprise identity federation.</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-10 space-y-10">
                            <form onSubmit={handleSave} className="space-y-10">
                                <div className="space-y-4">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">01 // Bridge Alias</Label>
                                    <Input
                                        placeholder="e.g., Corporate LDAP"
                                        value={editingConnector.name || ''}
                                        onChange={(e) => setEditingConnector({ ...editingConnector, name: e.target.value })}
                                        required
                                        className="h-14 border-none rounded-2xl bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-medium px-6"
                                    />
                                </div>

                                <div className="h-px bg-on-surface/5" />

                                {/* DYNAMIC FORM CONTENT */}
                                <div className="space-y-8">
                                    <div className="flex items-center gap-3">
                                        <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                                        <h3 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40">Credential Manifest</h3>
                                    </div>

                                    {editingConnector.type === 'scim' && (
                                        <div className="grid gap-6">
                                            <div className="space-y-3">
                                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Endpoint Protocol</Label>
                                                <Input
                                                    type="url"
                                                    placeholder="https://scim.identity.provider/v2"
                                                    value={editingConnector.endpoint || ''}
                                                    onChange={(e) => setEditingConnector({ ...editingConnector, endpoint: e.target.value })}
                                                    required
                                                    className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs px-5"
                                                />
                                            </div>
                                            <div className="space-y-3">
                                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Bearer Token</Label>
                                                <Input
                                                    type="password"
                                                    placeholder="••••••••••••••••"
                                                    value={editingConnector.credentials?.token || ''}
                                                    onChange={(e) => updateNested('credentials', 'token', e.target.value)}
                                                    required={isCreating}
                                                    className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all text-xs px-5"
                                                />
                                            </div>
                                        </div>
                                    )}

                                    {editingConnector.type === 'ldap' && (
                                        <div className="grid gap-6">
                                            <div className="space-y-3">
                                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Resource Locator (URL)</Label>
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
                                            <div className="space-y-3">
                                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Service Account Key (JSON)</Label>
                                                <textarea
                                                    className="flex min-h-[200px] w-full border-none rounded-2xl bg-surface-container/50 ring-1 ring-on-surface/5 p-6 font-mono text-[11px] leading-relaxed focus:outline-none focus:ring-2 focus:ring-primary/20 custom-scrollbar-dark text-on-surface"
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
                                        className="h-12 w-full md:w-auto px-10 rounded-xl bg-white ring-1 ring-on-surface/5 font-bold tracking-tight text-[11px] transition-all hover:bg-primary/5 hover:text-primary hover:ring-primary/20"
                                    >
                                        {testing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RotateCcw className="mr-2 h-4 w-4" />}
                                        Test Connectivity
                                    </Button>

                                    {testResult && (
                                        <div className={`p-4 rounded-xl border flex items-center gap-4 animate-in slide-in-from-left-4 duration-500 flex-1 ${testResult.status === 'success' ? 'bg-emerald-50 border-emerald-100 text-emerald-600' : 'bg-red-50 border-red-100 text-red-600'}`}>
                                            {testResult.status === 'success' ? <Check className="h-5 w-5" /> : <X className="h-5 w-5" />}
                                            <div className="flex flex-col">
                                                <span className="text-[11px] font-bold tracking-tight leading-none">{testResult.status === 'success' ? 'Handshake successful' : 'Handshake failed'}</span>
                                                {testResult.error && <span className="text-[10px] font-medium opacity-60 mt-1.5 truncate max-w-md">{testResult.error}</span>}
                                            </div>
                                        </div>
                                    )}
                                </div>

                                <div className="flex justify-end gap-4 pt-10 border-t border-on-surface/5">
                                    <Button
                                        type="button"
                                        variant="ghost"
                                        onClick={() => setEditingConnector(null)}
                                        className="h-12 px-10 rounded-xl font-bold text-[11px] tracking-tight text-on-surface-variant/40 hover:text-on-surface hover:bg-surface-container transition-all"
                                    >
                                        Discard
                                    </Button>
                                    <Button
                                        type="submit"
                                        className="h-12 rounded-xl font-bold text-[11px] tracking-tight px-12 shadow-xl shadow-primary/20 transition-all"
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
                icon={<Plug className="w-10 h-10 text-primary" />}
                title="Identity Bridges"
                description="Synchronize external identity shards with the core identity matrix. Multi-source provisioning for the zero-trust architecture."
            />

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <Button
                    variant="outline"
                    className="h-44 flex flex-col gap-5 items-center justify-center border-none bg-white hover:bg-primary/5 rounded-[32px] group transition-all relative overflow-hidden shadow-xl shadow-on-surface/5"
                    onClick={() => { setEditingConnector({ type: 'scim', enabled: true, credentials: {}, settings: {} }); setIsCreating(true); }}
                >
                    <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                        <Link2 className="w-20 h-20 -mr-4 -mt-4 text-primary" />
                    </div>
                    <div className="p-4 bg-primary/5 rounded-2xl group-hover:bg-primary group-hover:text-white transition-all text-primary">
                        <Plug className="h-7 w-7" />
                    </div>
                    <div className="flex flex-col items-center gap-1.5">
                        <span className="text-sm font-bold tracking-tight text-on-surface">Provision SCIM</span>
                        <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/20 italic">Direct API Handshake</span>
                    </div>
                </Button>

                <Button
                    variant="outline"
                    className="h-44 flex flex-col gap-5 items-center justify-center border-none bg-white hover:bg-primary/5 rounded-[32px] group transition-all relative overflow-hidden shadow-xl shadow-on-surface/5"
                    onClick={() => { setEditingConnector({ type: 'ldap', enabled: true, credentials: {}, settings: {} }); setIsCreating(true); }}
                >
                    <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                        <Database className="w-20 h-20 -mr-4 -mt-4 text-primary" />
                    </div>
                    <div className="p-4 bg-primary/5 rounded-2xl group-hover:bg-primary group-hover:text-white transition-all text-primary">
                        <span className="font-bold italic text-lg leading-none">LDAP</span>
                    </div>
                    <div className="flex flex-col items-center gap-1.5">
                        <span className="text-sm font-bold tracking-tight text-on-surface">Provision Directory</span>
                        <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/20 italic">Active Directory Sync</span>
                    </div>
                </Button>

                <Button
                    variant="outline"
                    className="h-44 flex flex-col gap-5 items-center justify-center border-none bg-white hover:bg-primary/5 rounded-[32px] group transition-all relative overflow-hidden shadow-xl shadow-on-surface/5"
                    onClick={() => { setEditingConnector({ type: 'azure-ad', enabled: true, credentials: {}, settings: {} }); setIsCreating(true); }}
                >
                    <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                        <ShieldCheck className="w-20 h-20 -mr-4 -mt-4 text-primary" />
                    </div>
                    <div className="p-4 bg-primary/5 rounded-2xl group-hover:bg-primary group-hover:text-white transition-all text-primary">
                        <span className="font-bold italic text-lg leading-none">ENTRA</span>
                    </div>
                    <div className="flex flex-col items-center gap-1.5">
                        <span className="text-sm font-bold tracking-tight text-on-surface">Provision Microsoft</span>
                        <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/20 italic">Graph API Federation</span>
                    </div>
                </Button>

                <Button
                    variant="outline"
                    className="h-44 flex flex-col gap-5 items-center justify-center border-none bg-white hover:bg-primary/5 rounded-[32px] group transition-all relative overflow-hidden shadow-xl shadow-on-surface/5"
                    onClick={() => { setEditingConnector({ type: 'google', enabled: true, credentials: {}, settings: { domain: '' } }); setIsCreating(true); }}
                >
                    <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                        <Fingerprint className="w-20 h-20 -mr-4 -mt-4 text-primary" />
                    </div>
                    <div className="p-4 bg-primary/5 rounded-2xl group-hover:bg-primary group-hover:text-white transition-all text-primary">
                        <span className="font-bold italic text-lg leading-none">GOOGLE</span>
                    </div>
                    <div className="flex flex-col items-center gap-1.5">
                        <span className="text-sm font-bold tracking-tight text-on-surface">Provision Workspace</span>
                        <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/20 italic">Delegated Sync Engine</span>
                    </div>
                </Button>
            </div>

            <div className="space-y-8">
                <div className="flex items-center gap-6">
                    <h2 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 italic flex-shrink-0">Active Bridge Nodes</h2>
                    <div className="h-px flex-1 bg-on-surface/5" />
                </div>

                <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-white overflow-hidden rounded-[32px]">
                    <GlassCardHeader className="py-8 px-10 border-b border-on-surface/5">
                        <div className="flex items-center gap-5">
                            <div className="p-3.5 bg-primary/5 rounded-2xl">
                                <Link2 className="w-7 h-7 text-primary" />
                            </div>
                            <div>
                                <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">Bridge Directory ({connectors.length})</GlassCardTitle>
                                <p className="text-on-surface-variant/20 font-bold text-[12px] mt-1 tracking-tight">Verified synchronization vectors establishing parity.</p>
                            </div>
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="p-0">
                        {connectors.length === 0 ? (
                            <div className="py-32 text-center text-sm font-medium text-on-surface-variant/30 italic">No identity bridges established in the current matrix.</div>
                        ) : (
                            <div className="divide-y divide-on-surface/5">
                                {connectors.map(c => (
                                    <div key={c.id} className="p-8 flex flex-col md:flex-row items-start md:items-center justify-between hover:bg-surface-container/10 transition-all group gap-8">
                                        <div className="flex items-center gap-8">
                                            <div className="w-14 h-14 rounded-2xl bg-surface-container/50 text-on-surface-variant/40 flex items-center justify-center transition-all group-hover:bg-primary group-hover:text-white group-hover:scale-105">
                                                <Plug className="h-6 w-6" />
                                            </div>
                                            <div className="flex flex-col gap-2">
                                                <div className="flex items-center gap-4">
                                                    <span className="text-lg font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{c.name}</span>
                                                    <Badge className="bg-surface-container/50 text-on-surface-variant/40 border-none rounded-lg font-bold text-[10px] tracking-tight px-3 py-1 group-hover:bg-primary/10 group-hover:text-primary transition-all">{c.type}</Badge>
                                                </div>
                                                <div className="flex items-center gap-3 text-[11px] font-bold tracking-tight text-on-surface-variant/20 group-hover:text-on-surface-variant/40 transition-opacity">
                                                    <Terminal className="h-3 w-3" />
                                                    Vector: {c.endpoint || 'Managed internal protocol'}
                                                </div>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-10 w-full md:w-auto mt-4 md:mt-0 pt-6 md:pt-0 border-t md:border-0 border-on-surface/5">
                                            <div className="flex items-center gap-5 px-5 py-3 rounded-2xl bg-surface-container/30 ring-1 ring-on-surface/5">
                                                <Switch
                                                    checked={c.enabled}
                                                    onCheckedChange={(checked) => handleToggle(c.id, checked)}
                                                    className="data-[state=checked]:bg-emerald-500"
                                                />
                                                <div className="flex flex-col">
                                                    <span className={`text-[11px] font-bold tracking-tight transition-all ${c.enabled ? 'text-emerald-600' : 'text-on-surface-variant/20'}`}>
                                                        {c.enabled ? 'Active' : 'Standby'}
                                                    </span>
                                                    <span className="text-[9px] font-bold tracking-tight opacity-20 italic">Sync Engine</span>
                                                </div>
                                            </div>

                                            <div className="flex gap-2">
                                                <Button size="icon" variant="ghost" className="h-11 w-11 rounded-xl text-on-surface-variant/40 hover:text-on-surface hover:bg-surface-container transition-all" onClick={() => { setEditingConnector(c); setIsCreating(false); }}>
                                                    <Settings className="h-5 w-5" />
                                                </Button>
                                                <Button size="icon" variant="ghost" className="h-11 w-11 rounded-xl text-on-surface-variant/40 hover:text-red-500 hover:bg-red-50 transition-all" onClick={() => handleDelete(c.id)}>
                                                    <Trash2 className="h-5 w-5" />
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
