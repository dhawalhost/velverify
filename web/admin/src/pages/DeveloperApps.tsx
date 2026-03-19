import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { getAppLogs, getAPIKeyLogs, api, lookupUser } from '../api';
import { Loader2, Plus, Smartphone, Trash2, RefreshCw, Key, AlertTriangle, Check, Terminal, Activity, X, Users, UserPlus, UserMinus, Pencil } from 'lucide-react';
import { Separator } from '@/components/ui/separator';

interface DeveloperApp {
    id: string;
    tenant_id?: string;
    name: string;
    description?: string;
    client_id: string;
    app_type: string;
    redirect_uris: string[];
    grant_types?: string[];
    scopes?: string[];
    status: string;
    created_at: string;
}

const AVAILABLE_SCOPES = ['openid', 'profile', 'email', 'offline_access'];
const AVAILABLE_GRANT_TYPES = ['authorization_code', 'refresh_token', 'client_credentials'];

interface APIKey {
    id: string;
    name: string;
    key_prefix: string;
    status: string;
    created_at: string;
}

const DeveloperApps: React.FC = () => {
    const currentTenantID = localStorage.getItem('tenantID') || '';
    const currentIssuerBaseURL = currentTenantID ? `${window.location.origin}/t/${currentTenantID}` : window.location.origin;
    const [apps, setApps] = useState<DeveloperApp[]>([]);
    const [apiKeys, setAPIKeys] = useState<APIKey[]>([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('apps');

    // Creation States
    const [createAppOpen, setCreateAppOpen] = useState(false);
    const [createKeyOpen, setCreateKeyOpen] = useState(false);

    const [newApp, setNewApp] = useState({
        name: '',
        description: '',
        redirect_uris: '',
        app_type: 'web',
        grant_types: ['authorization_code', 'refresh_token'],
        scopes: ['openid', 'profile', 'email'],
    });
    const [newKeyName, setNewKeyName] = useState('');
    const [editAppOpen, setEditAppOpen] = useState(false);
    const [editingApp, setEditingApp] = useState<{ id: string; name: string; description: string; redirect_uris: string; app_type: string; grant_types: string[]; scopes: string[] } | null>(null);
    const [quickstartApp, setQuickstartApp] = useState<DeveloperApp | null>(null);

    // Secrets Display
    const [createdSecret, setCreatedSecret] = useState<string | null>(null);
    const [createdAPIKey, setCreatedAPIKey] = useState<string | null>(null);
    const [error, setError] = useState('');
    const [successMessage, setSuccessMessage] = useState('');

    // Logs State
    const [logsOpen, setLogsOpen] = useState(false);
    const [viewingLogs, setViewingLogs] = useState<any[]>([]);
    const [logsLoading, setLogsLoading] = useState(false);
    const [selectedLogApp, setSelectedLogApp] = useState<{ id: string; name: string; type: 'app' | 'key' } | null>(null);
    const [expandedLogId, setExpandedLogId] = useState<string | null>(null);

    // Assignments State
    const [assignmentsOpen, setAssignmentsOpen] = useState(false);
    const [selectedAppAssignments, setSelectedAppAssignments] = useState<DeveloperApp | null>(null);
    const [assignedUsers, setAssignedUsers] = useState<string[]>([]);
    const [newAssignUser, setNewAssignUser] = useState("");
    const [assignmentSearch, setAssignmentSearch] = useState("");
    const [assignmentsLoading, setAssignmentsLoading] = useState(false);


    const fetchApps = async () => {
        try {
            const res = await api.get('/api/v1/apps');
            setApps(res.data.apps || []);
        } catch (err) { console.error(err); }
    };

    const fetchAPIKeys = async () => {
        try {
            const res = await api.get('/api/v1/api-keys');
            setAPIKeys(res.data.api_keys || []);
        } catch (err) { console.error(err); }
    };

    useEffect(() => {
        Promise.all([fetchApps(), fetchAPIKeys()]).finally(() => setLoading(false));
    }, []);

    useEffect(() => {
        if (!successMessage) return;
        const timer = setTimeout(() => setSuccessMessage(''), 4000);
        return () => clearTimeout(timer);
    }, [successMessage]);

    const parseRedirectURIs = (value: string) => value.split(',').map(u => u.trim()).filter(u => u);

    const validateRedirectURIs = (uris: string[]) => {
        if (uris.length === 0) return 'At least one redirect URI is required.';

        for (const uri of uris) {
            try {
                const parsed = new URL(uri);
                if (!['http:', 'https:'].includes(parsed.protocol)) {
                    return `Redirect URI must use http or https: ${uri}`;
                }
                if (parsed.hash) {
                    return `Redirect URI must not include a fragment: ${uri}`;
                }
            } catch {
                return `Redirect URI is not a valid URL: ${uri}`;
            }
        }

        return '';
    };

    const toggleScope = (target: 'new' | 'edit', scope: string) => {
        if (target === 'new') {
            setNewApp((prev) => ({
                ...prev,
                scopes: prev.scopes.includes(scope) ? prev.scopes.filter(s => s !== scope) : [...prev.scopes, scope]
            }));
            return;
        }

        if (!editingApp) return;
        setEditingApp({
            ...editingApp,
            scopes: editingApp.scopes.includes(scope) ? editingApp.scopes.filter(s => s !== scope) : [...editingApp.scopes, scope]
        });
    };

    const toggleGrantType = (target: 'new' | 'edit', grantType: string) => {
        if (target === 'new') {
            setNewApp((prev) => ({
                ...prev,
                grant_types: prev.grant_types.includes(grantType)
                    ? prev.grant_types.filter(g => g !== grantType)
                    : [...prev.grant_types, grantType]
            }));
            return;
        }

        if (!editingApp) return;
        setEditingApp({
            ...editingApp,
            grant_types: editingApp.grant_types.includes(grantType)
                ? editingApp.grant_types.filter(g => g !== grantType)
                : [...editingApp.grant_types, grantType]
        });
    };

    const getGrantTypeWarnings = (appType: string, grantTypes: string[]) => {
        const warnings: string[] = [];

        if ((appType === 'spa' || appType === 'native') && grantTypes.includes('client_credentials')) {
            warnings.push('SPA and Native apps should generally avoid client_credentials because client secrets cannot be safely protected in user devices/browsers.');
        }

        if (appType === 'machine' && grantTypes.includes('authorization_code')) {
            warnings.push('Machine-to-Machine apps typically use client_credentials instead of authorization_code.');
        }

        if (appType === 'web' && !grantTypes.includes('authorization_code')) {
            warnings.push('Web applications usually require authorization_code for interactive user login.');
        }

        if (grantTypes.includes('refresh_token') && !grantTypes.includes('authorization_code')) {
            warnings.push('refresh_token is usually paired with authorization_code.');
        }

        if (grantTypes.length === 0) {
            warnings.push('At least one grant type is required.');
        }

        return warnings;
    };

    const handleViewLogs = async (id: string, name: string, type: 'app' | 'key') => {
        setSelectedLogApp({ id, name, type });
        setLogsOpen(true);
        setLogsLoading(true);
        setViewingLogs([]);
        try {
            let data;
            if (type === 'app') {
                data = await getAppLogs(id);
            } else {
                data = await getAPIKeyLogs(id);
            }
            setViewingLogs(data.logs || []);
        } catch (err) {
            console.error("Failed to load logs", err);
        } finally {
            setLogsLoading(false);
        }
    };

    const handleManageAssignments = async (app: DeveloperApp) => {
        setError('');
        setNewAssignUser('');
        setAssignmentSearch('');
        setSelectedAppAssignments(app);
        setAssignmentsOpen(true);
        setAssignmentsLoading(true);
        try {
            const res = await api.get(`/api/v1/apps/${app.id}/assignments`);
            setAssignedUsers(res.data.users || []);
        } catch (err) { console.error(err) } finally {
            setAssignmentsLoading(false);
        }
    };

    const handleAssignUser = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!selectedAppAssignments || !newAssignUser) return;
        try {
            setError('');
            let userIDToAssign = newAssignUser.trim();

            if (userIDToAssign.includes('@')) {
                const lookup = await lookupUser(userIDToAssign);
                if (!lookup?.user_id) {
                    setError('Unable to resolve user email to user ID for assignment.');
                    return;
                }
                userIDToAssign = lookup.user_id;
            }

            const res = await api.post(`/api/v1/apps/${selectedAppAssignments.id}/assignments`, { user_id: userIDToAssign });
            if (res.status === 201) {
                setNewAssignUser("");
                // Refresh list
                const listRes = await api.get(`/api/v1/apps/${selectedAppAssignments.id}/assignments`);
                setAssignedUsers(listRes.data.users || []);
            }
        } catch (err: any) {
            console.error(err);
            setError(err?.response?.data?.error || 'Failed to assign user to application.');
        }
    };

    const handleUnassignUser = async (userId: string) => {
        if (!selectedAppAssignments) return;
        try {
            const res = await api.delete(`/api/v1/apps/${selectedAppAssignments.id}/assignments/${userId}`);
            if (res.status === 200) {
                const listRes = await api.get(`/api/v1/apps/${selectedAppAssignments.id}/assignments`);
                setAssignedUsers(listRes.data.users || []);
            }
        } catch (err) { console.error(err); }
    };

    const handleCreateApp = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setSuccessMessage('');
        setCreatedSecret(null);
        try {
            const redirectURIs = parseRedirectURIs(newApp.redirect_uris);
            const redirectValidationError = validateRedirectURIs(redirectURIs);
            if (redirectValidationError) {
                setError(redirectValidationError);
                return;
            }
            if (newApp.grant_types.length === 0) {
                setError('At least one grant type is required.');
                return;
            }
            const res = await api.post('/api/v1/apps', {
                name: newApp.name,
                description: newApp.description || null,
                redirect_uris: redirectURIs,
                grant_types: newApp.grant_types,
                scopes: newApp.scopes,
                app_type: newApp.app_type,
            });
            setCreatedSecret(res.data.client_secret);
            setCreateAppOpen(false);
            setNewApp({
                name: '',
                description: '',
                redirect_uris: '',
                app_type: 'web',
                grant_types: ['authorization_code', 'refresh_token'],
                scopes: ['openid', 'profile', 'email'],
            });
            fetchApps();
        } catch (err: any) {
            setError(err.response?.data?.error || err.message);
        }
    };

    const handleCreateAPIKey = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setSuccessMessage('');
        setCreatedAPIKey(null);
        try {
            const res = await api.post('/api/v1/api-keys', { name: newKeyName });
            setCreatedAPIKey(res.data.key);
            setCreateKeyOpen(false);
            setNewKeyName('');
            fetchAPIKeys();
        } catch (err: any) {
            setError(err.response?.data?.error || err.message);
        }
    };

    const handleOpenEditApp = (app: DeveloperApp) => {
        setError('');
        setSuccessMessage('');
        setEditingApp({
            id: app.id,
            name: app.name,
            description: app.description || '',
            redirect_uris: (app.redirect_uris || []).join(', '),
            app_type: app.app_type,
            grant_types: app.grant_types && app.grant_types.length > 0 ? app.grant_types : ['authorization_code', 'refresh_token'],
            scopes: app.scopes && app.scopes.length > 0 ? app.scopes : ['openid', 'profile', 'email'],
        });
        setEditAppOpen(true);
    };

    const handleUpdateApp = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!editingApp) return;

        setError('');
        setSuccessMessage('');
        try {
            const redirectURIs = parseRedirectURIs(editingApp.redirect_uris);
            const redirectValidationError = validateRedirectURIs(redirectURIs);
            if (redirectValidationError) {
                setError(redirectValidationError);
                return;
            }
            if (editingApp.grant_types.length === 0) {
                setError('At least one grant type is required.');
                return;
            }
            await api.put(`/api/v1/apps/${editingApp.id}`, {
                name: editingApp.name,
                description: editingApp.description || null,
                redirect_uris: redirectURIs,
                grant_types: editingApp.grant_types,
                scopes: editingApp.scopes,
                app_type: editingApp.app_type,
            });
            setEditAppOpen(false);
            setEditingApp(null);
            setSuccessMessage('Application updated successfully.');
            fetchApps();
        } catch (err: any) {
            setError(err?.response?.data?.error || err?.message || 'Failed to update application.');
        }
    };

    const handleDeleteApp = async (id: string) => {
        if (!window.confirm('Delete this app?')) return;
        await api.delete(`/api/v1/apps/${id}`);
        fetchApps();
    };

    const handleRevokeKey = async (id: string) => {
        if (!window.confirm('Revoke this API key?')) return;
        await api.delete(`/api/v1/api-keys/${id}`);
        fetchAPIKeys();
    };

    const handleRotateSecret = async (id: string) => {
        if (!window.confirm('Rotate this app\'s client secret? The old secret will stop working immediately.')) return;
        try {
            const res = await api.post(`/api/v1/apps/${id}/rotate-secret`);
            setCreatedSecret(res.data.client_secret);
        } catch (err) { console.error(err); }
    };

    const handleCopyValue = async (label: string, value: string) => {
        try {
            await navigator.clipboard.writeText(value);
            setError('');
            setSuccessMessage(`${label} copied to clipboard.`);
        } catch (err) {
            console.error(err);
            setError(`Failed to copy ${label.toLowerCase()}.`);
        }
    };

    const getQuickstartSnippet = (app: DeveloperApp) => {
        const primaryRedirectURI = app.redirect_uris?.[0] || 'http://localhost:3000/callback';
        return [
            `ISSUER_BASE_URL=${currentIssuerBaseURL}`,
            `CLIENT_ID=${app.client_id}`,
            `REDIRECT_URI=${primaryRedirectURI}`,
            `GRANT_TYPES=${(app.grant_types && app.grant_types.length > 0 ? app.grant_types : ['authorization_code', 'refresh_token']).join(' ')}`,
            `SCOPES=${(app.scopes && app.scopes.length > 0 ? app.scopes : ['openid', 'profile', 'email']).join(' ')}`,
        ].join('\n');
    };

    const filteredAssignedUsers = assignedUsers.filter((user) => user.toLowerCase().includes(assignmentSearch.toLowerCase().trim()));

    if (loading) return <div className="p-8 flex justify-center"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>;

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">Access & Credentials</h1>
                <p className="text-muted-foreground mt-1">Manage OAuth applications and API keys for integrations.</p>
                {currentTenantID && (
                    <p className="text-xs text-muted-foreground mt-2">Active Tenant: <span className="font-mono">{currentTenantID}</span></p>
                )}
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

            {successMessage && (
                <div className="bg-green-50 border border-green-200 dark:bg-green-900/20 dark:border-green-800 rounded-lg p-4">
                    <div className="flex items-start gap-3">
                        <div className="bg-green-100 p-2 rounded-full dark:bg-green-800 text-green-700 dark:text-green-300">
                            <Check className="h-5 w-5" />
                        </div>
                        <div className="flex-1 space-y-2">
                            <h4 className="font-semibold text-green-800 dark:text-green-300">Success</h4>
                            <p className="text-sm text-green-700 dark:text-green-400">{successMessage}</p>
                            <Button size="sm" className="bg-green-600 hover:bg-green-700 text-white border-none" onClick={() => setSuccessMessage('')}>
                                Dismiss
                            </Button>
                        </div>
                    </div>
                </div>
            )}

            {error && (
                <div className="bg-red-50 border border-red-200 dark:bg-red-900/20 dark:border-red-800 rounded-lg p-4">
                    <div className="flex items-start gap-3">
                        <div className="bg-red-100 p-2 rounded-full dark:bg-red-800 text-red-700 dark:text-red-300">
                            <AlertTriangle className="h-5 w-5" />
                        </div>
                        <div className="flex-1 space-y-2">
                            <h4 className="font-semibold text-red-800 dark:text-red-300">Error</h4>
                            <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
                            <Button size="sm" variant="outline" onClick={() => setError('')}>
                                Dismiss
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
                <Button
                    variant={activeTab === 'scim' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setActiveTab('scim')}
                    className="rounded-md"
                >
                    <RefreshCw className="mr-2 h-4 w-4" /> Directory Sync (SCIM)
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
                                    <div className="space-y-3 rounded-md border bg-muted/30 p-4">
                                        <div className="space-y-2">
                                            <Label>OIDC Issuer URL</Label>
                                            <div className="flex gap-2">
                                                <Input readOnly value={currentIssuerBaseURL} className="bg-muted font-mono text-xs" />
                                                <Button type="button" variant="outline" size="icon" onClick={() => handleCopyValue('Issuer URL', currentIssuerBaseURL)}>
                                                    <RefreshCw className="h-4 w-4" />
                                                </Button>
                                            </div>
                                            <div className="text-xs text-muted-foreground">Use issuer URL, client ID, and client secret in your OIDC client configuration.</div>
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Application Name</Label>
                                        <Input placeholder="e.g. Finance Portal" value={newApp.name} onChange={(e) => setNewApp({ ...newApp, name: e.target.value })} required />
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Redirect URIs</Label>
                                        <Input placeholder="https://app.wardseal.com/callback, http://localhost:3000" value={newApp.redirect_uris} onChange={(e) => setNewApp({ ...newApp, redirect_uris: e.target.value })} />
                                        <div className="text-xs text-muted-foreground">Comma separated absolute callback URLs. Fragments are not allowed.</div>
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Scopes</Label>
                                        <div className="grid grid-cols-2 gap-2">
                                            {AVAILABLE_SCOPES.map(scope => (
                                                <label key={scope} className="flex items-center gap-2 text-sm rounded-md border p-2 cursor-pointer">
                                                    <input
                                                        type="checkbox"
                                                        checked={newApp.scopes.includes(scope)}
                                                        onChange={() => toggleScope('new', scope)}
                                                    />
                                                    <span>{scope}</span>
                                                </label>
                                            ))}
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Grant Types</Label>
                                        <div className="grid grid-cols-1 gap-2">
                                            {AVAILABLE_GRANT_TYPES.map(grantType => (
                                                <label key={grantType} className="flex items-center gap-2 text-sm rounded-md border p-2 cursor-pointer">
                                                    <input
                                                        type="checkbox"
                                                        checked={newApp.grant_types.includes(grantType)}
                                                        onChange={() => toggleGrantType('new', grantType)}
                                                    />
                                                    <span>{grantType}</span>
                                                </label>
                                            ))}
                                        </div>
                                        {getGrantTypeWarnings(newApp.app_type, newApp.grant_types).length > 0 && (
                                            <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-800 dark:bg-amber-900/20 dark:border-amber-800 dark:text-amber-200 space-y-1">
                                                {getGrantTypeWarnings(newApp.app_type, newApp.grant_types).map((warning, index) => (
                                                    <div key={index} className="flex items-start gap-2">
                                                        <AlertTriangle className="h-3.5 w-3.5 mt-0.5" />
                                                        <span>{warning}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
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

                    {editAppOpen && editingApp && (
                        <Card className="max-w-xl mx-auto border-dashed">
                            <CardHeader>
                                <CardTitle>Edit Application</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <form onSubmit={handleUpdateApp} className="space-y-4">
                                    <div className="space-y-3 rounded-md border bg-muted/30 p-4">
                                        <div className="space-y-2">
                                            <Label>OIDC Issuer URL</Label>
                                            <div className="flex gap-2">
                                                <Input readOnly value={currentIssuerBaseURL} className="bg-muted font-mono text-xs" />
                                                <Button type="button" variant="outline" size="icon" onClick={() => handleCopyValue('Issuer URL', currentIssuerBaseURL)}>
                                                    <RefreshCw className="h-4 w-4" />
                                                </Button>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Application Name</Label>
                                        <Input value={editingApp.name} onChange={(e) => setEditingApp({ ...editingApp, name: e.target.value })} required />
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Description</Label>
                                        <Input value={editingApp.description} onChange={(e) => setEditingApp({ ...editingApp, description: e.target.value })} />
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Redirect URIs</Label>
                                        <Input value={editingApp.redirect_uris} onChange={(e) => setEditingApp({ ...editingApp, redirect_uris: e.target.value })} />
                                        <div className="text-xs text-muted-foreground">Comma separated absolute callback URLs. Fragments are not allowed.</div>
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Scopes</Label>
                                        <div className="grid grid-cols-2 gap-2">
                                            {AVAILABLE_SCOPES.map(scope => (
                                                <label key={scope} className="flex items-center gap-2 text-sm rounded-md border p-2 cursor-pointer">
                                                    <input
                                                        type="checkbox"
                                                        checked={editingApp.scopes.includes(scope)}
                                                        onChange={() => toggleScope('edit', scope)}
                                                    />
                                                    <span>{scope}</span>
                                                </label>
                                            ))}
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Grant Types</Label>
                                        <div className="grid grid-cols-1 gap-2">
                                            {AVAILABLE_GRANT_TYPES.map(grantType => (
                                                <label key={grantType} className="flex items-center gap-2 text-sm rounded-md border p-2 cursor-pointer">
                                                    <input
                                                        type="checkbox"
                                                        checked={editingApp.grant_types.includes(grantType)}
                                                        onChange={() => toggleGrantType('edit', grantType)}
                                                    />
                                                    <span>{grantType}</span>
                                                </label>
                                            ))}
                                        </div>
                                        {getGrantTypeWarnings(editingApp.app_type, editingApp.grant_types).length > 0 && (
                                            <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-800 dark:bg-amber-900/20 dark:border-amber-800 dark:text-amber-200 space-y-1">
                                                {getGrantTypeWarnings(editingApp.app_type, editingApp.grant_types).map((warning, index) => (
                                                    <div key={index} className="flex items-start gap-2">
                                                        <AlertTriangle className="h-3.5 w-3.5 mt-0.5" />
                                                        <span>{warning}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                    <div className="space-y-2">
                                        <Label>Type</Label>
                                        <select
                                            className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                                            value={editingApp.app_type}
                                            onChange={(e) => setEditingApp({ ...editingApp, app_type: e.target.value })}
                                        >
                                            <option value="web">Web Application</option>
                                            <option value="spa">Single Page App</option>
                                            <option value="native">Native Mobile</option>
                                            <option value="machine">Machine-to-Machine</option>
                                        </select>
                                    </div>
                                    <div className="flex gap-2">
                                        <Button type="button" variant="outline" className="w-full" onClick={() => { setEditAppOpen(false); setEditingApp(null); }}>Cancel</Button>
                                        <Button type="submit" className="w-full">Save Changes</Button>
                                    </div>
                                </form>
                            </CardContent>
                        </Card>
                    )}

                    {!createAppOpen && !editAppOpen && (
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
                                        <div className="flex items-center gap-1">
                                            <Button size="icon" variant="ghost" className="h-8 w-8" onClick={() => handleOpenEditApp(app)}>
                                                <Pencil className="h-4 w-4" />
                                            </Button>
                                            <Button size="icon" variant="ghost" className="h-8 w-8 text-destructive hover:bg-destructive/10" onClick={() => handleDeleteApp(app.id)}>
                                                <Trash2 className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>
                                </CardHeader>
                                <CardContent className="space-y-3 pb-3">
                                    <div>
                                        <div className="text-xs font-medium text-muted-foreground mb-1">Tenant</div>
                                        <div className="bg-muted px-2 py-1 rounded text-xs font-mono truncate">{app.tenant_id || currentTenantID || 'unknown'}</div>
                                    </div>
                                    <div>
                                        <div className="text-xs font-medium text-muted-foreground mb-1">Client ID</div>
                                        <div className="bg-muted px-2 py-1 rounded text-xs font-mono select-all truncate">{app.client_id}</div>
                                    </div>
                                    <div>
                                        <div className="text-xs font-medium text-muted-foreground mb-1">Scopes</div>
                                        <div className="flex flex-wrap gap-1">
                                            {(app.scopes && app.scopes.length > 0 ? app.scopes : ['openid', 'profile', 'email']).map(scope => (
                                                <Badge key={scope} variant="secondary" className="text-[10px]">{scope}</Badge>
                                            ))}
                                        </div>
                                    </div>
                                    <div>
                                        <div className="text-xs font-medium text-muted-foreground mb-1">Grant Types</div>
                                        <div className="flex flex-wrap gap-1">
                                            {(app.grant_types && app.grant_types.length > 0 ? app.grant_types : ['authorization_code', 'refresh_token']).map(grantType => (
                                                <Badge key={grantType} variant="outline" className="text-[10px]">{grantType}</Badge>
                                            ))}
                                        </div>
                                    </div>
                                </CardContent>
                                <CardFooter className="pt-0 flex flex-wrap gap-2">
                                    <Button variant="outline" size="sm" className="flex-1 text-xs" onClick={() => handleRotateSecret(app.id)}>
                                        <RefreshCw className="mr-2 h-3 w-3" /> Rotate Secret
                                    </Button>
                                    <Button variant="outline" size="sm" className="flex-1 text-xs" onClick={() => handleManageAssignments(app)}>
                                        <Users className="mr-2 h-3 w-3" /> Assignments
                                    </Button>
                                    <Button variant="outline" size="sm" className="flex-1 text-xs" onClick={() => setQuickstartApp(app)}>
                                        <Terminal className="mr-2 h-3 w-3" /> Quickstart
                                    </Button>
                                    <Button variant="secondary" size="sm" className="w-full text-xs" onClick={() => handleViewLogs(app.id, app.name, 'app')}>
                                        <Activity className="mr-2 h-3 w-3" /> View Logs
                                    </Button>
                                </CardFooter>
                                </Card>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {quickstartApp && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
                    <div className="bg-card w-full max-w-3xl max-h-[90vh] flex flex-col rounded-lg shadow-lg border">
                        <div className="flex items-center justify-between p-4 border-b">
                            <div>
                                <h3 className="text-lg font-semibold flex items-center gap-2">
                                    <Terminal className="h-5 w-5 text-primary" /> Quickstart: {quickstartApp.name}
                                </h3>
                                <p className="text-xs text-muted-foreground">Copy these values into your OIDC client application.</p>
                            </div>
                            <Button variant="ghost" size="icon" onClick={() => setQuickstartApp(null)}>
                                <X className="h-5 w-5" />
                            </Button>
                        </div>
                        <div className="p-4 space-y-4 overflow-y-auto">
                            <div className="grid gap-4 md:grid-cols-2">
                                <div className="space-y-2">
                                    <Label>Issuer URL</Label>
                                    <div className="flex gap-2">
                                        <Input readOnly value={currentIssuerBaseURL} className="bg-muted font-mono text-xs" />
                                        <Button type="button" variant="outline" size="icon" onClick={() => handleCopyValue('Issuer URL', currentIssuerBaseURL)}>
                                            <RefreshCw className="h-4 w-4" />
                                        </Button>
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <Label>Client ID</Label>
                                    <div className="flex gap-2">
                                        <Input readOnly value={quickstartApp.client_id} className="bg-muted font-mono text-xs" />
                                        <Button type="button" variant="outline" size="icon" onClick={() => handleCopyValue('Client ID', quickstartApp.client_id)}>
                                            <RefreshCw className="h-4 w-4" />
                                        </Button>
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <Label>Primary Redirect URI</Label>
                                    <div className="flex gap-2">
                                        <Input readOnly value={quickstartApp.redirect_uris?.[0] || ''} className="bg-muted font-mono text-xs" />
                                        <Button type="button" variant="outline" size="icon" onClick={() => handleCopyValue('Redirect URI', quickstartApp.redirect_uris?.[0] || '')}>
                                            <RefreshCw className="h-4 w-4" />
                                        </Button>
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-2">
                                <Label>Environment Snippet</Label>
                                <div className="bg-muted rounded-md border p-3 font-mono text-xs whitespace-pre-wrap break-all">
                                    {getQuickstartSnippet(quickstartApp)}
                                </div>
                                <Button type="button" variant="outline" size="sm" onClick={() => handleCopyValue('Quickstart snippet', getQuickstartSnippet(quickstartApp))}>
                                    <Terminal className="mr-2 h-4 w-4" /> Copy Snippet
                                </Button>
                            </div>

                            <div className="space-y-2">
                                <Label>Registered Redirect URIs</Label>
                                <div className="space-y-2">
                                    {(quickstartApp.redirect_uris || []).map((uri, index) => (
                                        <div key={`${uri}-${index}`} className="flex gap-2">
                                            <Input readOnly value={uri} className="bg-muted font-mono text-xs" />
                                            <Button type="button" variant="outline" size="icon" onClick={() => handleCopyValue(`Redirect URI ${index + 1}`, uri)}>
                                                <RefreshCw className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
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
                                                <div className="flex gap-2">
                                                    <Button size="sm" variant="outline" className="text-muted-foreground hover:bg-muted" onClick={() => handleViewLogs(key.id, key.name, 'key')}>
                                                        <Activity className="mr-2 h-4 w-4" /> Logs
                                                    </Button>
                                                    <Button size="sm" variant="outline" className="text-destructive hover:bg-destructive/10 hover:text-destructive border-destructive/20" onClick={() => handleRevokeKey(key.id)}>
                                                        Revoke
                                                    </Button>
                                                </div>
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
                            <CardDescription>Use this issuer with your client credentials to configure WardSeal as an IdP in external applications (Okta, Azure AD, Auth0).</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="space-y-4">
                                <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">OpenID Connect (OIDC)</h3>
                                <div className="grid gap-4 md:grid-cols-1">
                                    <div className="space-y-2">
                                        <Label>Issuer URL</Label>
                                        <div className="flex gap-2">
                                            <Input readOnly value={currentIssuerBaseURL} className="bg-muted font-mono text-xs" />
                                            <Button variant="outline" size="icon" onClick={() => navigator.clipboard.writeText(currentIssuerBaseURL)}>
                                                <RefreshCw className="h-4 w-4" />
                                            </Button>
                                        </div>
                                        <p className="text-xs text-muted-foreground">Configure your client with issuer URL, client ID, and client secret. OIDC libraries auto-discover the rest.</p>
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

            {/* SCIM Instructions Section */}
            {activeTab === 'scim' && (
                <div className="space-y-6">
                    <Card>
                        <CardHeader>
                            <CardTitle>Inbound Directory Sync (SCIM)</CardTitle>
                            <CardDescription>
                                Wardseal natively supports the SCIM 2.0 protocol. You can configure identity providers like Okta or Azure AD to automatically push user and group changes directly into Wardseal in real-time.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="bg-muted p-4 rounded-md space-y-2">
                                <h4 className="font-semibold text-sm">Connection Details</h4>
                                <div className="grid grid-cols-1 md:grid-cols-[150px_1fr] gap-2 items-center">
                                    <div className="text-sm text-muted-foreground">SCIM Base URL:</div>
                                    <code className="bg-background px-2 py-1 rounded text-sm break-all font-mono select-all">
                                        {window.location.origin}/scim/v2
                                    </code>
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-[150px_1fr] gap-2 items-center">
                                    <div className="text-sm text-muted-foreground">Authentication:</div>
                                    <div className="text-sm font-medium flex items-center gap-2">
                                        HTTP Header (OAuth Bearer Token)
                                    </div>
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-[150px_1fr] gap-2 items-center">
                                    <div className="text-sm text-muted-foreground">Secret Token:</div>
                                    <div className="text-sm text-muted-foreground italic">
                                        Generate a new <span className="text-primary cursor-pointer hover:underline" onClick={() => setActiveTab('keys')}>API Key</span> and paste it here.
                                    </div>
                                </div>
                            </div>

                            <Separator />

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div className="space-y-3">
                                    <div className="flex items-center gap-2">
                                        <div className="h-6 w-6 rounded bg-blue-600 flex items-center justify-center text-white text-xs font-bold">A</div>
                                        <h4 className="font-semibold">Azure AD Setup</h4>
                                    </div>
                                    <ol className="text-sm text-muted-foreground space-y-2 list-decimal list-outside ml-4">
                                        <li>In Azure Portal, go to <strong>Enterprise Applications</strong>.</li>
                                        <li>Click <strong>New application</strong> &gt; <strong>Create your own application</strong>.</li>
                                        <li>Select "Integrate any other application you don't find in the gallery (Non-gallery)".</li>
                                        <li>In the app menu, select <strong>Provisioning</strong> and click <strong>Get started</strong>.</li>
                                        <li>Set Provisioning Mode to <strong>Automatic</strong>.</li>
                                        <li>Expand Admin Credentials.</li>
                                        <li>Paste the <strong>SCIM Base URL</strong> into Tenant URL.</li>
                                        <li>Paste your <strong>API Key</strong> into Secret Token.</li>
                                        <li>Click <strong>Test Connection</strong> and save.</li>
                                    </ol>
                                </div>

                                <div className="space-y-3">
                                    <div className="flex items-center gap-2">
                                        <div className="h-6 w-6 rounded bg-slate-800 flex items-center justify-center text-white text-xs font-bold">O</div>
                                        <h4 className="font-semibold">Okta Setup</h4>
                                    </div>
                                    <ol className="text-sm text-muted-foreground space-y-2 list-decimal list-outside ml-4">
                                        <li>In Okta Admin interface, go to <strong>Applications</strong>.</li>
                                        <li>Create a new App Integration using <strong>SWA (Secure Web Authentication)</strong> or an existing SCIM template.</li>
                                        <li>Go to the <strong>Provisioning</strong> tab and click <strong>Configure API Integration</strong>.</li>
                                        <li>Check <strong>Enable API Integration</strong>.</li>
                                        <li>Select <strong>HTTP Header</strong> authentication.</li>
                                        <li>Paste the <strong>SCIM Base URL</strong> into the Base URL field.</li>
                                        <li>Paste your <strong>API Key</strong> into the API Token field.</li>
                                        <li>Click <strong>Test API Credentials</strong> and save.</li>
                                    </ol>
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                </div>
            )}

            {/* Application Assignments Modal */}
            {assignmentsOpen && selectedAppAssignments && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
                    <div className="bg-card w-full max-w-2xl max-h-[90vh] flex flex-col rounded-lg shadow-lg border">
                        <div className="flex items-center justify-between p-4 border-b">
                            <div>
                                <h3 className="text-lg font-semibold flex items-center gap-2">
                                    <Users className="h-5 w-5 text-primary" /> Application Assignees: {selectedAppAssignments.name}
                                </h3>
                                <p className="text-xs text-muted-foreground">Only assigned users can interactively log into this OAuth application.</p>
                            </div>
                            <div className="flex items-center gap-2">
                                <Badge variant="secondary" className="text-xs">{assignedUsers.length} assigned</Badge>
                                <Button variant="ghost" size="icon" onClick={() => setAssignmentsOpen(false)}>
                                    <X className="h-5 w-5" />
                                </Button>
                            </div>
                        </div>

                        <div className="p-4 border-b bg-muted/20 space-y-3">
                            <div className="grid gap-2 sm:grid-cols-2">
                                <div className="rounded-md border bg-background px-3 py-2">
                                    <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Application Type</div>
                                    <div className="text-sm font-medium mt-1">{selectedAppAssignments.app_type}</div>
                                </div>
                                <div className="rounded-md border bg-background px-3 py-2">
                                    <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Access Control</div>
                                    <div className="text-sm font-medium mt-1">Assignment Required</div>
                                </div>
                            </div>

                            <form onSubmit={handleAssignUser} className="flex flex-col sm:flex-row gap-2">
                                <Input
                                    placeholder="Enter user ID or email"
                                    className="flex-1"
                                    value={newAssignUser}
                                    onChange={(e) => setNewAssignUser(e.target.value)}
                                    required
                                />
                                <Button type="submit" className="sm:w-auto w-full">
                                    <UserPlus className="mr-2 h-4 w-4" /> Grant Access
                                </Button>
                            </form>
                            <p className="text-xs text-muted-foreground">You can paste either a user ID or email. Email is resolved automatically.</p>

                            <div className="flex gap-2">
                                <Input
                                    placeholder="Search assigned users"
                                    value={assignmentSearch}
                                    onChange={(e) => setAssignmentSearch(e.target.value)}
                                    className="flex-1"
                                />
                                {assignmentSearch && (
                                    <Button type="button" variant="outline" onClick={() => setAssignmentSearch('')}>Clear</Button>
                                )}
                            </div>
                        </div>

                        <div className="p-4 flex-1 overflow-y-auto">
                            {assignmentsLoading ? (
                                <div className="py-8 flex justify-center"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
                            ) : assignedUsers.length === 0 ? (
                                <div className="py-8 text-center text-muted-foreground bg-muted/20 rounded-lg border border-dashed">No users are assigned yet. No one can log into this app.</div>
                            ) : filteredAssignedUsers.length === 0 ? (
                                <div className="py-8 text-center text-muted-foreground bg-muted/20 rounded-lg border border-dashed">No assigned users match your search.</div>
                            ) : (
                                <div className="grid gap-2">
                                    {filteredAssignedUsers.map(user => (
                                        <div key={user} className="flex justify-between items-center p-3 rounded-md border bg-background hover:bg-muted/30">
                                            <div className="flex items-center gap-3 min-w-0">
                                                <div className="bg-primary/10 text-primary rounded-full p-2 shrink-0">
                                                    <Users className="h-4 w-4" />
                                                </div>
                                                <span className="font-mono text-sm truncate">{user}</span>
                                            </div>
                                            <Button variant="ghost" size="sm" className="text-destructive hover:bg-destructive/10" onClick={() => handleUnassignUser(user)}>
                                                <UserMinus className="h-4 w-4 mr-2" /> Revoke
                                            </Button>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                        <div className="p-4 border-t flex justify-end">
                            <Button type="button" variant="outline" onClick={() => setAssignmentsOpen(false)}>Done</Button>
                        </div>
                    </div>
                </div>
            )}

            {/* API Logs Modal */}
            {logsOpen && selectedLogApp && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
                    <div className="bg-card w-full max-w-4xl max-h-[90vh] flex flex-col rounded-lg shadow-lg border">
                        <div className="flex items-center justify-between p-4 border-b">
                            <div>
                                <h3 className="text-lg font-semibold flex items-center gap-2">
                                    <Activity className="h-5 w-5 text-primary" /> API Logs: {selectedLogApp.name}
                                </h3>
                                <p className="text-xs text-muted-foreground">Showing the latest 50 API requests.</p>
                            </div>
                            <Button variant="ghost" size="icon" onClick={() => setLogsOpen(false)}>
                                <X className="h-5 w-5" />
                            </Button>
                        </div>
                        <div className="p-4 flex-1 overflow-y-auto">
                            {logsLoading ? (
                                <div className="py-12 flex justify-center"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
                            ) : viewingLogs.length === 0 ? (
                                <div className="py-12 text-center text-muted-foreground bg-muted/20 rounded-lg border border-dashed">No API requests recorded yet.</div>
                            ) : (
                                <div className="space-y-4">
                                    {viewingLogs.map((log) => (
                                        <div key={log.id} className="border rounded-md overflow-hidden text-sm">
                                            <div
                                                className="bg-muted/30 px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-muted/50 transition-colors"
                                                onClick={() => setExpandedLogId(expandedLogId === log.id ? null : log.id)}
                                            >
                                                <div className="flex items-center gap-4">
                                                    <span className={`font-mono font-medium px-2 py-0.5 rounded text-xs ${log.status_code >= 400 ? 'bg-red-500/10 text-red-500' : 'bg-green-500/10 text-green-500'}`}>
                                                        {log.status_code}
                                                    </span>
                                                    <span className="font-mono font-medium w-12">{log.method}</span>
                                                    <span className="font-mono truncate max-w-[300px]">{log.path}</span>
                                                </div>
                                                <div className="flex items-center gap-4 text-muted-foreground">
                                                    <span className="tabular-nums">{log.latency_ms}ms</span>
                                                    <span>{new Date(log.created_at).toLocaleString()}</span>
                                                </div>
                                            </div>

                                            {expandedLogId === log.id && (
                                                <div className="p-4 border-t bg-background grid grid-cols-2 gap-4 h-[300px] overflow-hidden">
                                                    <div className="flex flex-col h-full">
                                                        <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2 shrink-0">Request Payload</h4>
                                                        <div className="bg-muted/30 rounded p-2 overflow-auto flex-1 font-mono text-xs whitespace-pre">
                                                            {log.request_payload || '{}'}
                                                        </div>
                                                    </div>
                                                    <div className="flex flex-col h-full">
                                                        <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2 shrink-0">Response Payload</h4>
                                                        <div className="bg-muted/30 rounded p-2 overflow-auto flex-1 font-mono text-xs whitespace-pre">
                                                            {log.response_payload || '{}'}
                                                        </div>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DeveloperApps;
