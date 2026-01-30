import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Loader2, Plus, Smartphone, Trash2, RefreshCw, Key, AlertTriangle, Check, Terminal } from 'lucide-react';
import { Separator } from '@/components/ui/separator';

interface DeveloperApp {
    id: string;
    name: string;
    description?: string;
    client_id: string;
    app_type: string;
    redirect_uris: string[];
    status: string;
    created_at: string;
}

interface APIKey {
    id: string;
    name: string;
    key_prefix: string;
    status: string;
    created_at: string;
}

const DeveloperApps: React.FC = () => {
    const [apps, setApps] = useState<DeveloperApp[]>([]);
    const [apiKeys, setAPIKeys] = useState<APIKey[]>([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('apps');

    // Creation States
    const [createAppOpen, setCreateAppOpen] = useState(false);
    const [createKeyOpen, setCreateKeyOpen] = useState(false);

    const [newApp, setNewApp] = useState({ name: '', description: '', redirect_uris: '', app_type: 'web' });
    const [newKeyName, setNewKeyName] = useState('');

    // Secrets Display
    const [createdSecret, setCreatedSecret] = useState<string | null>(null);
    const [createdAPIKey, setCreatedAPIKey] = useState<string | null>(null);
    const [error, setError] = useState('');

    const headers = () => ({
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'X-Tenant-ID': localStorage.getItem('tenantID') || '',
        'X-User-ID': localStorage.getItem('userId') || '',
        'Content-Type': 'application/json',
    });

    const fetchApps = async () => {
        try {
            const res = await fetch('/api/v1/apps', { headers: headers() });
            if (res.ok) {
                const data = await res.json();
                setApps(data.apps || []);
            }
        } catch (err) { console.error(err); }
    };

    const fetchAPIKeys = async () => {
        try {
            const res = await fetch('/api/v1/api-keys', { headers: headers() });
            if (res.ok) {
                const data = await res.json();
                setAPIKeys(data.api_keys || []);
            }
        } catch (err) { console.error(err); }
    };

    useEffect(() => {
        Promise.all([fetchApps(), fetchAPIKeys()]).finally(() => setLoading(false));
    }, []);

    const handleCreateApp = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setCreatedSecret(null);
        try {
            const res = await fetch('/api/v1/apps', {
                method: 'POST',
                headers: headers(),
                body: JSON.stringify({
                    name: newApp.name,
                    description: newApp.description || null,
                    redirect_uris: newApp.redirect_uris.split(',').map(u => u.trim()).filter(u => u),
                    app_type: newApp.app_type,
                }),
            });
            const data = await res.json();
            if (res.ok) {
                setCreatedSecret(data.client_secret);
                setCreateAppOpen(false);
                setNewApp({ name: '', description: '', redirect_uris: '', app_type: 'web' });
                fetchApps();
            } else {
                setError(data.error || 'Failed to create app');
            }
        } catch (err: any) {
            setError(err.message);
        }
    };

    const handleCreateAPIKey = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setCreatedAPIKey(null);
        try {
            const res = await fetch('/api/v1/api-keys', {
                method: 'POST',
                headers: headers(),
                body: JSON.stringify({ name: newKeyName }),
            });
            const data = await res.json();
            if (res.ok) {
                setCreatedAPIKey(data.key);
                setCreateKeyOpen(false);
                setNewKeyName('');
                fetchAPIKeys();
            } else {
                setError(data.error || 'Failed to create API key');
            }
        } catch (err: any) {
            setError(err.message);
        }
    };

    const handleDeleteApp = async (id: string) => {
        if (!window.confirm('Delete this app?')) return;
        await fetch(`/api/v1/apps/${id}`, { method: 'DELETE', headers: headers() });
        fetchApps();
    };

    const handleRevokeKey = async (id: string) => {
        if (!window.confirm('Revoke this API key?')) return;
        await fetch(`/api/v1/api-keys/${id}`, { method: 'DELETE', headers: headers() });
        fetchAPIKeys();
    };

    const handleRotateSecret = async (id: string) => {
        if (!window.confirm('Rotate this app\'s client secret? The old secret will stop working immediately.')) return;
        const res = await fetch(`/api/v1/apps/${id}/rotate-secret`, { method: 'POST', headers: headers() });
        if (res.ok) {
            const data = await res.json();
            setCreatedSecret(data.client_secret);
        }
    };

    if (loading) return <div className="p-8 flex justify-center"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>;

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">Access & Credentials</h1>
                <p className="text-muted-foreground mt-1">Manage OAuth applications and API keys for integrations.</p>
            </div>

            {/* Secret Display Alert */}
            {(createdSecret || createdAPIKey) && (
                <div className="bg-green-50 border border-green-200 dark:bg-green-900/20 dark:border-green-800 rounded-lg p-4 animate-in fade-in slide-in-from-top-4">
                    <div className="flex items-start gap-3">
                        <div className="bg-green-100 p-2 rounded-full dark:bg-green-800 text-green-700 dark:text-green-300">
                            <Check className="h-5 w-5" />
                        </div>
                        <div className="flex-1 space-y-2">
                            <h4 className="font-semibold text-green-800 dark:text-green-300">Credentials Created Successfully</h4>
                            <p className="text-sm text-green-700 dark:text-green-400">Please copy your secret/key now. You won't be able to see it again.</p>
                            <div className="bg-white dark:bg-black/50 border border-green-200 dark:border-green-800 p-3 rounded-md font-mono text-sm break-all select-all">
                                {createdSecret || createdAPIKey}
                            </div>
                            <Button size="sm" className="bg-green-600 hover:bg-green-700 text-white border-none" onClick={() => { setCreatedSecret(null); setCreatedAPIKey(null); }}>
                                I have saved it
                            </Button>
                        </div>
                    </div>
                </div>
            )}

            {/* Main Tabs */}
            <div className="flex bg-muted p-1 rounded-lg w-fit">
                <Button
                    variant={activeTab === 'apps' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setActiveTab('apps')}
                    className="rounded-md"
                >
                    <Smartphone className="mr-2 h-4 w-4" /> OAuth Apps
                </Button>
                <Button
                    variant={activeTab === 'keys' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setActiveTab('keys')}
                    className="rounded-md"
                >
                    <Key className="mr-2 h-4 w-4" /> API Keys
                </Button>
                <Button
                    variant={activeTab === 'idp' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setActiveTab('idp')}
                    className="rounded-md"
                >
                    <Smartphone className="mr-2 h-4 w-4" /> IdP Settings
                </Button>
            </div>

            {/* OAuth Apps Section */}
            {activeTab === 'apps' && (
                <div className="space-y-6">
                    <div className="flex justify-end">
                        <Button onClick={() => setCreateAppOpen(!createAppOpen)}>
                            {createAppOpen ? 'Cancel' : <><Plus className="mr-2 h-4 w-4" /> Create App</>}
                        </Button>
                    </div>

                    {createAppOpen && (
                        <Card className="max-w-xl mx-auto border-dashed">
                            <CardHeader>
                                <CardTitle>Create New Application</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <form onSubmit={handleCreateApp} className="space-y-4">
                                    <div className="space-y-2">
                                        <Label>Application Name</Label>
                                        <Input placeholder="e.g. Finance Portal" value={newApp.name} onChange={(e) => setNewApp({ ...newApp, name: e.target.value })} required />
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Redirect URIs</Label>
                                        <Input placeholder="https://app.wardseal.com/callback, http://localhost:3000" value={newApp.redirect_uris} onChange={(e) => setNewApp({ ...newApp, redirect_uris: e.target.value })} />
                                        <div className="text-xs text-muted-foreground">Comma separated URIs</div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <Label>Type</Label>
                                            <select
                                                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                                                value={newApp.app_type}
                                                onChange={(e) => setNewApp({ ...newApp, app_type: e.target.value })}
                                            >
                                                <option value="web">Web Application</option>
                                                <option value="spa">Single Page App</option>
                                                <option value="native">Native Mobile</option>
                                                <option value="machine">Machine-to-Machine</option>
                                            </select>
                                        </div>
                                    </div>
                                    <Button type="submit" className="w-full">Create Application</Button>
                                </form>
                            </CardContent>
                        </Card>
                    )}

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {apps.map(app => (
                            <Card key={app.id}>
                                <CardHeader className="pb-3">
                                    <div className="flex justify-between items-start">
                                        <div>
                                            <CardTitle className="flex items-center gap-2">
                                                {app.name}
                                                <Badge variant="outline" className="text-xs font-normal">{app.app_type}</Badge>
                                            </CardTitle>
                                            <CardDescription className="mt-1">{app.description || "No description"}</CardDescription>
                                        </div>
                                        <Button size="icon" variant="ghost" className="h-8 w-8 text-destructive hover:bg-destructive/10" onClick={() => handleDeleteApp(app.id)}>
                                            <Trash2 className="h-4 w-4" />
                                        </Button>
                                    </div>
                                </CardHeader>
                                <CardContent className="space-y-3 pb-3">
                                    <div>
                                        <div className="text-xs font-medium text-muted-foreground mb-1">Client ID</div>
                                        <div className="bg-muted px-2 py-1 rounded text-xs font-mono select-all truncate">{app.client_id}</div>
                                    </div>
                                </CardContent>
                                <CardFooter className="pt-0">
                                    <Button variant="outline" size="sm" className="w-full text-xs" onClick={() => handleRotateSecret(app.id)}>
                                        <RefreshCw className="mr-2 h-3 w-3" /> Rotate Secret
                                    </Button>
                                </CardFooter>
                            </Card>
                        ))}
                    </div>
                </div>
            )}

            {/* API Keys Section */}
            {activeTab === 'keys' && (
                <div className="space-y-6">
                    <div className="flex justify-end">
                        <Button onClick={() => setCreateKeyOpen(!createKeyOpen)}>
                            {createKeyOpen ? 'Cancel' : <><Plus className="mr-2 h-4 w-4" /> New API Key</>}
                        </Button>
                    </div>

                    {createKeyOpen && (
                        <Card className="max-w-xl mx-auto border-dashed">
                            <CardHeader>
                                <CardTitle>Generate API Key</CardTitle>
                                <CardDescription>Create a long-lived token for programmatic access.</CardDescription>
                            </CardHeader>
                            <CardContent>
                                <form onSubmit={handleCreateAPIKey} className="space-y-4">
                                    <div className="space-y-2">
                                        <Label>Key Name</Label>
                                        <Input placeholder="e.g. CI/CD Runner" value={newKeyName} onChange={(e) => setNewKeyName(e.target.value)} required />
                                    </div>
                                    <Button type="submit" className="w-full">Generate Key</Button>
                                </form>
                            </CardContent>
                        </Card>
                    )}

                    <Card>
                        <CardHeader>
                            <CardTitle>Active API Keys</CardTitle>
                        </CardHeader>
                        <CardContent className="p-0">
                            <div className="p-0">
                                {apiKeys.length === 0 ? (
                                    <div className="p-8 text-center text-muted-foreground">No API keys active.</div>
                                ) : (
                                    <div className="divide-y">
                                        {apiKeys.map(key => (
                                            <div key={key.id} className="flex items-center justify-between p-4">
                                                <div className="flex items-center gap-3">
                                                    <div className="p-2 bg-muted rounded-full">
                                                        <Terminal className="h-4 w-4 text-foreground" />
                                                    </div>
                                                    <div>
                                                        <div className="font-medium">{key.name}</div>
                                                        <div className="text-xs text-muted-foreground flex gap-2 items-center">
                                                            <span className="font-mono bg-muted/50 px-1 rounded">{key.key_prefix}...</span>
                                                            <span>• Created {new Date(key.created_at).toLocaleDateString()}</span>
                                                        </div>
                                                    </div>
                                                </div>
                                                <Button size="sm" variant="outline" className="text-destructive hover:bg-destructive/10 hover:text-destructive border-destructive/20" onClick={() => handleRevokeKey(key.id)}>
                                                    Revoke
                                                </Button>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </CardContent>
                    </Card>
                </div>
            )}
            {/* IdP Settings Section */}
            {activeTab === 'idp' && (
                <div className="space-y-6">
                    <Card>
                        <CardHeader>
                            <CardTitle>Identity Provider Configuration</CardTitle>
                            <CardDescription>Use these endpoints to configure Wardseal as an IdP in external applications (Okta, Azure AD, Auth0).</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="space-y-4">
                                <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">OpenID Connect (OIDC)</h3>
                                <div className="grid gap-4 md:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label>Issuer URL</Label>
                                        <div className="flex gap-2">
                                            <Input readOnly value={window.location.origin} className="bg-muted font-mono text-xs" />
                                            <Button variant="outline" size="icon" onClick={() => navigator.clipboard.writeText(window.location.origin)}>
                                                <RefreshCw className="h-4 w-4" />
                                            </Button>
                                        </div>
                                        <p className="text-xs text-muted-foreground">The root URL for OIDC discovery.</p>
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Authorization Endpoint</Label>
                                        <div className="flex gap-2">
                                            <Input readOnly value={`${window.location.origin}/oauth2/authorize`} className="bg-muted font-mono text-xs" />
                                            <Button variant="outline" size="icon" onClick={() => navigator.clipboard.writeText(`${window.location.origin}/oauth2/authorize`)}>
                                                <RefreshCw className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Token Endpoint</Label>
                                        <div className="flex gap-2">
                                            <Input readOnly value={`${window.location.origin}/oauth2/token`} className="bg-muted font-mono text-xs" />
                                            <Button variant="outline" size="icon" onClick={() => navigator.clipboard.writeText(`${window.location.origin}/oauth2/token`)}>
                                                <RefreshCw className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <Label>JWKS URI</Label>
                                        <div className="flex gap-2">
                                            <Input readOnly value={`${window.location.origin}/.well-known/jwks.json`} className="bg-muted font-mono text-xs" />
                                            <Button variant="outline" size="icon" onClick={() => navigator.clipboard.writeText(`${window.location.origin}/.well-known/jwks.json`)}>
                                                <RefreshCw className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <Separator />

                            <div className="space-y-4">
                                <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">SAML 2.0</h3>
                                <div className="grid gap-4 md:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label>Metadata URL</Label>
                                        <div className="flex gap-2">
                                            <Input readOnly value={`${window.location.origin}/saml/metadata`} className="bg-muted font-mono text-xs" />
                                            <Button variant="outline" size="icon" onClick={() => navigator.clipboard.writeText(`${window.location.origin}/saml/metadata`)}>
                                                <RefreshCw className="h-4 w-4" />
                                            </Button>
                                        </div>
                                        <p className="text-xs text-muted-foreground">Upload this URL or file to your Service Provider.</p>
                                    </div>
                                    <div className="space-y-2">
                                        <Label>SSO URL (ACS)</Label>
                                        <div className="flex gap-2">
                                            <Input readOnly value={`${window.location.origin}/saml/sso`} className="bg-muted font-mono text-xs" />
                                            <Button variant="outline" size="icon" onClick={() => navigator.clipboard.writeText(`${window.location.origin}/saml/sso`)}>
                                                <RefreshCw className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                </div>
            )}
        </div>
    );
};

export default DeveloperApps;
