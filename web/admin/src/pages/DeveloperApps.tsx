import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import {
    getAppLogs,
    getAPIKeyLogs,
    api,
    lookupUser,
    getSAMLProviders,
    createSAMLProvider,
    deleteSAMLProvider,
    SAMLServiceProvider
} from '../api';
import {
    Loader2,
    Plus,
    Smartphone,
    Trash2,
    RefreshCw,
    Key,
    AlertTriangle,
    Check,
    Terminal,
    Activity,
    X,
    Users,
    UserPlus,
    UserMinus,
    Pencil,
    ShieldCheck,
    Lock,
    Code2,
    Globe,
    Copy,
    ExternalLink,
    Search,
    Box,
    Sparkles,
    Zap,
    Cpu,
    Fingerprint,
    ArrowUpRight,
    Shield
} from 'lucide-react';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import {
    PageHeader,
    GlassCard,
    GlassCardHeader,
    GlassCardTitle,
    GlassCardContent,
    GlassTable,
    GlassTableHeader,
    GlassTableHead,
    GlassTableRow,
    GlassCardDescription, PageLayout
} from '@/components/layout';
import { TableBody, TableCell } from '@/components/ui/table';
import { OAuthAppCard } from '../components/OAuthAppCard';
import { APIKeyRow } from '../components/APIKeyRow';
import { SAMLProviderRow } from '../components/SAMLProviderRow';


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
    const [samlProviders, setSAMLProviders] = useState<SAMLServiceProvider[]>([]);
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

    const [newSAMLProvider, setNewSAMLProvider] = useState<SAMLServiceProvider>({
        entity_id: '',
        metadata_url: '',
        acs_url: '',
        sign_assertions: true,
        encrypt_assertions: false,
    });
    const [createSAMLOpen, setCreateSAMLOpen] = useState(false);
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

    const fetchSAMLProviders = async () => {
        try {
            const res = await getSAMLProviders();
            setSAMLProviders(res.providers || []);
        } catch (err) { console.error(err); }
    };

    useEffect(() => {
        Promise.all([fetchApps(), fetchAPIKeys(), fetchSAMLProviders()]).finally(() => setLoading(false));
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

    const handleCreateSAMLProvider = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        try {
            await createSAMLProvider(newSAMLProvider);
            setCreateSAMLOpen(false);
            setNewSAMLProvider({ entity_id: '', metadata_url: '', acs_url: '', sign_assertions: true, encrypt_assertions: false });
            fetchSAMLProviders();
            setSuccessMessage('SAML Service Provider registered successfully.');
        } catch (err: any) {
            setError(err.response?.data?.error || err.message);
        }
    };

    const handleDeleteSAMLProvider = async (entityID: string) => {
        if (!window.confirm(`Delete SAML registration for ${entityID}?`)) return;
        try {
            await deleteSAMLProvider(entityID);
            fetchSAMLProviders();
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
        <PageLayout>
        <div className="space-y-10 animate-in fade-in duration-700">
            <PageHeader
                icon={<Code2 className="w-6 h-6 text-primary" />}
                title="Applications & API Keys"
                description="Manage your OAuth2 applications, API keys, and external service integrations."
            />

            {/* Secret/Key Alerts: MODERNIST */}
            {(createdSecret || createdAPIKey) && (
                <div className="bg-success-subtle ring-1 ring-emerald-500/20 p-5 rounded-xl relative overflow-hidden group animate-in slide-in-from-top-4">
                    <div className="absolute top-0 right-0 p-4 opacity-5">
                        <Lock className="w-20 h-20 text-emerald-900" />
                    </div>
                    <div className="relative z-10 flex flex-col md:flex-row items-center gap-6">
                        <div className="p-3 bg-card rounded-xl shadow-sm">
                            <ShieldCheck className="h-6 w-6 text-success" />
                        </div>
                        <div className="flex-1 space-y-2">
                            <h4 className="text-lg font-bold tracking-tight text-emerald-900">Secret Created</h4>
                            <p className="text-[12px] font-semibold text-emerald-900/40 max-w-2xl">
                                Your new secret has been generated. Please copy and save it securely; it will not be shown again.
                            </p>
                            <div className="bg-card/50 backdrop-blur-sm p-4 font-mono text-[11px] break-all rounded-xl ring-1 ring-emerald-500/10 flex items-center justify-between">
                                <span className="text-emerald-950 font-bold tracking-tight">{createdSecret || createdAPIKey}</span>
                                <Button
                                    variant="ghost"
                                    size="icon"
                                    className="ml-4 h-8 w-8 hover:bg-success/10"
                                    onClick={() => handleCopyValue('Credential', createdSecret || createdAPIKey || '')}
                                >
                                    <Copy className="h-3.5 w-3.5" />
                                </Button>
                            </div>
                            <Button
                                className="bg-emerald-600 text-white rounded-lg font-bold text-[10px] px-6 h-8 hover:bg-emerald-700 shadow-lg shadow-emerald-600/10"
                                onClick={() => { setCreatedSecret(null); setCreatedAPIKey(null); }}
                            >
                                Done
                            </Button>
                        </div>
                    </div>
                </div>
            )}

            {/* Success/Error Alerts */}
            {successMessage && (
                <div className="bg-success-subtle ring-1 ring-emerald-500/20 rounded-xl p-3 text-emerald-700 font-bold text-[10px] tracking-tight flex items-center gap-2">
                    <div className="p-1 bg-success/10 rounded-lg">
                        <Check className="h-3 w-3 text-success" />
                    </div>
                    {successMessage}
                </div>
            )}
            {error && (
                <div className="bg-destructive/10 ring-1 ring-destructive/20 rounded-xl p-3 text-red-700 font-bold text-[10px] tracking-tight flex items-center gap-2">
                    <div className="p-1 bg-destructive/100/10 rounded-lg">
                        <AlertTriangle className="h-3 w-3 text-destructive" />
                    </div>
                    {error}
                </div>
            )}

            {/* TABS: CLEAN MODERNIST */}
            <Tabs defaultValue="apps" className="w-full" onValueChange={setActiveTab}>
                <TabsList className="h-auto p-1 bg-surface-container/50 rounded-xl ring-1 ring-on-surface/5 flex flex-wrap gap-1 mb-6">
                    <TabsTrigger
                        value="apps"
                        className="h-8 px-5 rounded-lg data-[state=active]:bg-card data-[state=active]:text-primary data-[state=active]:shadow-sm font-bold text-[10px] tracking-tight transition-all text-on-surface-variant/40 hover:text-on-surface"
                    >
                        <Smartphone className="mr-1.5 h-3 w-3" /> Applications
                    </TabsTrigger>
                    <TabsTrigger
                        value="keys"
                        className="h-8 px-5 rounded-lg data-[state=active]:bg-card data-[state=active]:text-primary data-[state=active]:shadow-sm font-bold text-[10px] tracking-tight transition-all text-on-surface-variant/40 hover:text-on-surface"
                    >
                        <Key className="mr-1.5 h-3 w-3" /> API Keys
                    </TabsTrigger>
                    <TabsTrigger
                        value="idp"
                        className="h-8 px-5 rounded-lg data-[state=active]:bg-card data-[state=active]:text-primary data-[state=active]:shadow-sm font-bold text-[10px] tracking-tight transition-all text-on-surface-variant/40 hover:text-on-surface"
                    >
                        <Shield className="mr-1.5 h-3 w-3" /> SAML
                    </TabsTrigger>
                    <TabsTrigger
                        value="scim"
                        className="h-8 px-5 rounded-lg data-[state=active]:bg-card data-[state=active]:text-primary data-[state=active]:shadow-sm font-bold text-[10px] tracking-tight transition-all text-on-surface-variant/40 hover:text-on-surface"
                    >
                        <RefreshCw className="mr-1.5 h-3 w-3" /> SCIM
                    </TabsTrigger>
                </TabsList>

                {/* OAuth Apps Content */}
                <TabsContent value="apps" className="space-y-10 animate-in fade-in duration-500">
                    <div className="flex justify-between items-center bg-card rounded-xl p-4 shadow-xl shadow-on-surface/5 ring-1 ring-on-surface/5">
                        <div className="flex items-center gap-3">
                            <div className="p-2 bg-primary/10 rounded-lg">
                                <Zap className="w-4 h-4 text-primary" />
                            </div>
                            <div className="flex flex-col">
                                <span className="text-on-surface font-bold text-sm tracking-tight leading-none">Register Application</span>
                                <span className="text-on-surface-variant/40 font-semibold text-[10px] mt-1 tracking-tight uppercase">New OAuth2 Client</span>
                            </div>
                        </div>
                        <Button
                            onClick={() => setCreateAppOpen(!createAppOpen)}
                            className="bg-primary text-primary-foreground rounded-lg font-bold text-[11px] px-5 h-8 shadow-lg shadow-primary/10"
                        >
                            {createAppOpen ? 'Cancel' : <><Plus className="mr-1.5 h-3.5 w-3.5" /> Add App</>}
                        </Button>
                    </div>

                    {createAppOpen && (
                        <GlassCard className="border-none shadow-2xl shadow-on-surface/5 overflow-hidden rounded-xl scale-in-center bg-card">
                            <GlassCardHeader className="bg-surface-container p-6">
                                <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">New Application</GlassCardTitle>
                                <p className="text-on-surface-variant/60 font-medium text-[10px] mt-1">Provide details to register your application.</p>
                            </GlassCardHeader>
                            <GlassCardContent className="p-6 space-y-6">
                                <form onSubmit={handleCreateApp} className="space-y-6">
                                    <div className="grid gap-10 md:grid-cols-2">
                                        <div className="space-y-1.5">
                                            <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Name</Label>
                                            <Input
                                                placeholder="e.g. CORE_SERVICE"
                                                value={newApp.name}
                                                onChange={(e) => setNewApp({ ...newApp, name: e.target.value })}
                                                required
                                                className="h-9 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium px-4"
                                            />
                                        </div>
                                        <div className="space-y-1.5">
                                            <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Type</Label>
                                            <select
                                                className="flex h-9 w-full rounded-lg border-none bg-surface-container/30 px-4 font-medium text-[11px] ring-1 ring-on-surface/5 outline-none focus-visible:ring-2 focus-visible:ring-primary/20 transition-all appearance-none"
                                                value={newApp.app_type}
                                                onChange={(e) => setNewApp({ ...newApp, app_type: e.target.value })}
                                            >
                                                <option value="web">Web Application</option>
                                                <option value="spa">Single Page App</option>
                                                <option value="native">Native Mobile</option>
                                                <option value="machine">Machine to Machine</option>
                                            </select>
                                        </div>
                                    </div>

                                    <div className="space-y-2.5">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Redirect URIs (comma-separated)</Label>
                                        <Input
                                            placeholder="https://app.domain/callback"
                                            value={newApp.redirect_uris}
                                            onChange={(e) => setNewApp({ ...newApp, redirect_uris: e.target.value })}
                                            className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-mono text-sm p-6"
                                        />
                                    </div>

                                    <div className="grid gap-6 md:grid-cols-2">
                                        <div className="space-y-3">
                                            <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Scopes</Label>
                                            <div className="grid grid-cols-2 gap-2">
                                                {AVAILABLE_SCOPES.map(scope => (
                                                    <label key={scope} className={`flex items-center gap-2 p-2.5 rounded-xl cursor-pointer transition-all ring-1 ${newApp.scopes.includes(scope) ? 'bg-primary/5 ring-primary/20' : 'bg-surface-container/10 ring-on-surface/5 hover:ring-on-surface/10'}`}>
                                                        <input
                                                            type="checkbox"
                                                            checked={newApp.scopes.includes(scope)}
                                                            onChange={() => toggleScope('new', scope)}
                                                            className="h-3.5 w-3.5 rounded-lg border-on-surface/20 text-primary focus:ring-primary/20"
                                                        />
                                                        <span className="text-[10px] font-bold tracking-tight text-on-surface/60">{scope}</span>
                                                    </label>
                                                ))}
                                            </div>
                                        </div>
                                        <div className="space-y-3">
                                            <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Flows</Label>
                                            <div className="space-y-2">
                                                {AVAILABLE_GRANT_TYPES.map(grantType => (
                                                    <label key={grantType} className={`flex items-center gap-2 p-2.5 rounded-xl cursor-pointer transition-all ring-1 ${newApp.grant_types.includes(grantType) ? 'bg-primary/5 ring-primary/20 text-primary' : 'bg-surface-container/10 ring-on-surface/5 hover:ring-on-surface/10 text-on-surface/60'}`}>
                                                        <input
                                                            type="checkbox"
                                                            checked={newApp.grant_types.includes(grantType)}
                                                            onChange={() => toggleGrantType('new', grantType)}
                                                            className="h-3.5 w-3.5 rounded-lg border-on-surface/20 text-primary focus:ring-primary/20"
                                                        />
                                                        <span className="text-[10px] font-bold tracking-tight">{grantType.replace('_', ' ')}</span>
                                                    </label>
                                                ))}
                                            </div>
                                        </div>
                                    </div>

                                    <Button type="submit" className="w-full h-10 rounded-xl font-bold text-[13px] tracking-tight shadow-xl shadow-primary/20">
                                        Register Application
                                    </Button>
                                </form>
                            </GlassCardContent>
                        </GlassCard>
                    )}

                    {/* APPS GRID: MODERNIST CARDS */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {apps.map(app => (
                            <OAuthAppCard
                                key={app.id}
                                app={app}
                                handleOpenEditApp={handleOpenEditApp}
                                handleDeleteApp={handleDeleteApp}
                                handleRotateSecret={handleRotateSecret}
                                handleManageAssignments={handleManageAssignments}
                                setQuickstartApp={setQuickstartApp}
                                handleViewLogs={handleViewLogs}
                            />
                        ))}
                    </div>
                </TabsContent>

                {/* API Keys Content */}
                <TabsContent value="keys" className="space-y-10 animate-in fade-in duration-500">
                    <div className="flex justify-end">
                        <Button
                            onClick={() => setCreateKeyOpen(!createKeyOpen)}
                            className="bg-primary text-primary-foreground rounded-lg font-bold text-[11px] px-6 h-9 shadow-lg shadow-primary/10 transition-all"
                        >
                            {createKeyOpen ? 'Abort' : <><Plus className="mr-1.5 h-4 w-4" /> Generate Key</>}
                        </Button>
                    </div>

                    {createKeyOpen && (
                        <GlassCard className="max-w-2xl mx-auto border-none shadow-2xl rounded-xl bg-card overflow-hidden">
                            <GlassCardHeader className="bg-surface-container p-6">
                                <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">Create API Key</GlassCardTitle>
                                <GlassCardDescription className="text-[10px] font-medium text-on-surface-variant/40 mt-1">Create an API key for programmatic access to the WardSeal API.</GlassCardDescription>
                            </GlassCardHeader>
                            <GlassCardContent className="p-6">
                                <form onSubmit={handleCreateAPIKey} className="space-y-6">
                                    <div className="space-y-1.5">
                                        <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Key Alias</Label>
                                        <Input
                                            placeholder="PROGRAMMATIC_LABEL"
                                            value={newKeyName}
                                            onChange={(e) => setNewKeyName(e.target.value)}
                                            required
                                            className="h-9 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium px-4"
                                        />
                                    </div>
                                    <Button type="submit" className="w-full h-10 rounded-lg font-bold text-[13px] tracking-tight shadow-xl shadow-primary/20">
                                        Generate Key
                                    </Button>
                                </form>
                            </GlassCardContent>
                        </GlassCard>
                    )}

                    <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                        <GlassCardHeader className="bg-surface-container/30 border-b border-on-surface/5 p-6">
                            <div className="flex items-center gap-4">
                                <div className="p-2.5 bg-primary/10 rounded-xl">
                                    <Terminal className="w-5 h-5 text-primary" />
                                </div>
                                <div className="space-y-0.5">
                                    <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">All API Keys</GlassCardTitle>
                                    <p className="text-[9px] font-bold uppercase tracking-widest text-on-surface-variant/40">{apiKeys.length} Active keys</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-0">
                            {apiKeys.length === 0 ? (
                                <div className="py-24 text-center text-sm font-medium text-on-surface-variant/20 italic">No API keys found.</div>
                            ) : (
                                <div className="divide-y divide-on-surface/5">
                                    {apiKeys.map(key => (
                                        <APIKeyRow
                                            key={key.id}
                                            apiKey={key}
                                            handleViewLogs={handleViewLogs}
                                            handleRevokeKey={handleRevokeKey}
                                        />
                                    ))}
                                </div>
                            )}
                        </GlassCardContent>
                    </GlassCard>
                </TabsContent>

                {/* IdP Settings Content */}
                <TabsContent value="idp" className="space-y-6 animate-in fade-in duration-500">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card rounded-xl overflow-hidden ring-1 ring-on-surface/5">
                            <GlassCardHeader className="bg-surface-container p-6 relative overflow-hidden">
                                <div className="absolute top-0 right-0 p-6 opacity-[0.03]">
                                    <Globe className="w-20 h-20" />
                                </div>
                                <div className="relative z-10 space-y-2">
                                    <div className="flex items-center gap-3">
                                        <Badge className="bg-primary/10 text-primary rounded-lg h-6 font-bold text-[9px] tracking-tight px-2.5 border-none">Protocol</Badge>
                                        <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/40">OpenID Connect</span>
                                    </div>
                                    <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">OIDC Configuration</GlassCardTitle>
                                    <p className="text-xs font-medium text-on-surface-variant/40">Public endpoints for your OIDC integration.</p>
                                </div>
                            </GlassCardHeader>
                            <GlassCardContent className="p-6 space-y-6">
                                <div className="space-y-4 flex-1">
                                    <div className="space-y-2">
                                        <Label className="text-[10px] font-bold uppercase tracking-wider text-on-surface-variant/50 ml-1">Discovery Issuer URL</Label>
                                        <div className="flex gap-2">
                                            <Input readOnly value={currentIssuerBaseURL} className="h-9 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 font-mono text-[10px] px-4" />
                                            <Button variant="ghost" className="h-9 w-9 rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 p-0 hover:bg-primary hover:text-primary-foreground transition-all shadow-sm" onClick={() => handleCopyValue('Issuer URL', currentIssuerBaseURL)}>
                                                <Copy className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>
                                    <div className="p-4 bg-primary/5 rounded-xl ring-1 ring-primary/10 space-y-2">
                                        <div className="flex items-center gap-3">
                                            <Shield className="h-5 w-5 text-primary" />
                                            <span className="text-[11px] font-bold uppercase tracking-widest text-primary">How to use</span>
                                        </div>
                                        <p className="text-xs font-medium text-on-surface-variant/60 leading-relaxed">
                                            Your application should use the well-known configuration endpoint.
                                        </p>
                                        <div className="font-mono text-[9px] text-on-surface-variant/40 truncate bg-card/50 p-2 rounded-lg ring-1 ring-on-surface/5">
                                            GET {currentIssuerBaseURL}/.well-known/openid-configuration
                                        </div>
                                    </div>
                                </div>
                            </GlassCardContent>
                        </GlassCard>

                        <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card rounded-xl overflow-hidden ring-1 ring-on-surface/5">
                            <GlassCardHeader className="bg-surface-container p-6 relative overflow-hidden">
                                <div className="absolute top-0 right-0 p-6 opacity-[0.03]">
                                    <ShieldCheck className="w-20 h-20" />
                                </div>
                                <div className="relative z-10 space-y-2">
                                    <div className="flex items-center gap-3">
                                        <Badge className="bg-primary/10 text-primary rounded-lg h-6 font-bold text-[9px] tracking-tight px-2.5 border-none">Enterprise</Badge>
                                        <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/40">SAML 2.0</span>
                                    </div>
                                    <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">SAML Configuration</GlassCardTitle>
                                    <p className="text-xs font-medium text-on-surface-variant/40">Public endpoints for your SAML integration.</p>
                                </div>
                            </GlassCardHeader>
                            <GlassCardContent className="p-6 space-y-6">
                                <div className="space-y-4">
                                    <div className="space-y-2">
                                        <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Metadata URL</Label>
                                        <div className="flex gap-2">
                                            <Input readOnly value={`${window.location.origin}/saml/metadata`} className="h-9 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 font-mono text-[10px] px-4" />
                                            <Button variant="ghost" className="h-9 w-9 rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 p-0 hover:bg-primary hover:text-primary-foreground transition-all shadow-sm" onClick={() => handleCopyValue('Metadata URL', `${window.location.origin}/saml/metadata`)}>
                                                <Copy className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">ACS URL</Label>
                                        <div className="flex gap-2">
                                            <Input readOnly value={`${window.location.origin}/saml/sso`} className="h-9 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 font-mono text-[10px] px-4" />
                                            <Button variant="ghost" className="h-9 w-9 rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 p-0 hover:bg-primary hover:text-primary-foreground transition-all shadow-sm" onClick={() => handleCopyValue('SSO URL', `${window.location.origin}/saml/sso`)}>
                                                <Copy className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>
                                </div>
                            </GlassCardContent>
                        </GlassCard>
                    </div>

                    {/* SAML SPs Registry */}
                    <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card rounded-xl overflow-hidden ring-1 ring-on-surface/5">
                        <GlassCardHeader className="bg-surface-container p-6 flex flex-row items-center justify-between">
                            <div className="flex items-center gap-4">
                                <div className="p-3 bg-primary rounded-xl">
                                    <Zap className="w-5 h-5 text-white" />
                                </div>
                                <div className="space-y-0.5">
                                    <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">Service Providers</GlassCardTitle>
                                    <p className="text-[9px] font-bold uppercase tracking-widest text-on-surface-variant/40">SAML Service Providers</p>
                                </div>
                            </div>
                            <Button
                                onClick={() => setCreateSAMLOpen(!createSAMLOpen)}
                                className="bg-card text-primary rounded-xl font-bold text-[11px] px-6 h-9 shadow-sm ring-1 ring-on-surface/5 hover:ring-on-surface/10"
                            >
                                {createSAMLOpen ? 'Cancel' : <><Plus className="mr-2 h-4 w-4" /> Add Provider</>}
                            </Button>
                        </GlassCardHeader>
                        <GlassCardContent className="p-0">
                            {createSAMLOpen && (
                                <div className="p-6 border-b border-on-surface/5 bg-surface-container/10 animate-in slide-in-from-top-4 duration-500">
                                    <form onSubmit={handleCreateSAMLProvider} className="space-y-6">
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                            <div className="space-y-2">
                                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Entity ID</Label>
                                                <Input
                                                    placeholder="https://sp.provider.com/saml"
                                                    value={newSAMLProvider.entity_id}
                                                    onChange={e => setNewSAMLProvider({ ...newSAMLProvider, entity_id: e.target.value })}
                                                    required
                                                    className="h-9 border-none rounded-xl bg-card ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-mono text-[10px] px-4"
                                                />
                                            </div>
                                            <div className="space-y-2">
                                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">ACS URL</Label>
                                                <Input
                                                    placeholder="https://sp.provider.com/saml/acs"
                                                    value={newSAMLProvider.acs_url}
                                                    onChange={e => setNewSAMLProvider({ ...newSAMLProvider, acs_url: e.target.value })}
                                                    required
                                                    className="h-9 border-none rounded-xl bg-card ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-mono text-[10px] px-4"
                                                />
                                            </div>
                                        </div>
                                        <div className="flex flex-wrap gap-4">
                                            <div className="flex items-center gap-3 p-3 bg-card rounded-xl ring-1 ring-on-surface/5 shadow-sm">
                                                <Switch
                                                    checked={newSAMLProvider.sign_assertions}
                                                    onCheckedChange={checked => setNewSAMLProvider({ ...newSAMLProvider, sign_assertions: checked })}
                                                    className="data-[state=checked]:bg-success scale-75"
                                                />
                                                <div className="flex flex-col">
                                                    <span className="text-[11px] font-bold tracking-tight text-on-surface">Sign Response</span>
                                                    <span className="text-[9px] font-medium text-on-surface-variant/40">Crypto Integrity</span>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-3 p-3 bg-card rounded-xl ring-1 ring-on-surface/5 shadow-sm">
                                                <Switch
                                                    checked={newSAMLProvider.encrypt_assertions}
                                                    onCheckedChange={checked => setNewSAMLProvider({ ...newSAMLProvider, encrypt_assertions: checked })}
                                                    className="data-[state=checked]:bg-success scale-75"
                                                />
                                                <div className="flex flex-col">
                                                    <span className="text-[11px] font-bold tracking-tight text-on-surface">Encrypt Response</span>
                                                    <span className="text-[9px] font-medium text-on-surface-variant/40">Data Privacy</span>
                                                </div>
                                            </div>
                                        </div>

                                        <Button type="submit" className="w-full h-10 rounded-xl font-bold text-xs shadow-lg shadow-primary/20">
                                            Add Provider
                                        </Button>
                                    </form>
                                </div>
                            )}

                            {samlProviders.length === 0 ? (
                                <div className="py-24 text-center text-sm font-medium text-on-surface-variant/20 italic">No service providers registered.</div>
                            ) : (
                                <div className="divide-y divide-on-surface/5">
                                    {samlProviders.map(sp => (
                                        <SAMLProviderRow
                                            key={sp.entity_id}
                                            sp={sp}
                                            handleDeleteSAMLProvider={handleDeleteSAMLProvider}
                                        />
                                    ))}
                                </div>
                            )}
                        </GlassCardContent>
                    </GlassCard>
                </TabsContent>

                {/* SCIM Content */}
                <TabsContent value="scim" className="space-y-6 animate-in fade-in duration-500">
                    <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card rounded-xl overflow-hidden ring-1 ring-on-surface/5">
                        <GlassCardHeader className="bg-surface-container p-6 relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-6 opacity-[0.02]">
                                <RefreshCw className="w-24 h-24" />
                            </div>
                            <div className="relative z-10 space-y-2">
                                <div className="flex items-center gap-3">
                                    <Badge className="bg-primary/10 text-primary rounded-lg h-6 font-bold text-[9px] tracking-tight px-3">Provisioning</Badge>
                                    <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/40">Enabled</span>
                                </div>
                                <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface leading-tight">SCIM Directory Sync</GlassCardTitle>
                                <p className="text-xs font-medium text-on-surface-variant/60 max-w-2xl leading-relaxed">
                                    Configure your identity provider (Azure AD, Okta) to automatically sync users and groups to WardSeal.
                                </p>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-6 space-y-8">
                            {/* Connection Specs */}
                            <div className="space-y-6">
                                <h3 className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 border-b border-on-surface/5 pb-3">SCIM Settings</h3>
                                <div className="grid gap-6 md:grid-cols-2">
                                    <div className="p-4 bg-card ring-1 ring-on-surface/5 rounded-xl space-y-2 shadow-sm">
                                        <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">SCIM URL</Label>
                                        <div className="flex gap-2">
                                            <Input readOnly value={`${window.location.origin}/scim/v2`} className="h-9 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 font-mono text-[10px] px-4" />
                                            <Button variant="ghost" className="h-9 w-9 rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 p-0 hover:bg-primary hover:text-primary-foreground transition-all shadow-sm" onClick={() => handleCopyValue('SCIM URL', `${window.location.origin}/scim/v2`)}>
                                                <Copy className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </div>
                                    <div className="p-4 bg-card ring-1 ring-on-surface/5 rounded-xl space-y-2 shadow-sm">
                                        <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Authentication Flow</Label>
                                        <div className="h-9 flex items-center px-4 bg-primary/10 rounded-xl text-primary font-bold text-[10px] tracking-tight ring-1 ring-primary/20">
                                            HTTP Bearer Token (OAuth2)
                                        </div>
                                    </div>
                                </div>
                                <div className="p-6 bg-surface-container/30 rounded-xl flex flex-col md:flex-row items-center justify-between gap-6 ring-1 ring-on-surface/5 border-2 border-dashed border-on-surface/5">
                                    <div className="flex items-center gap-4">
                                        <div className="p-3 bg-card rounded-xl shadow-sm cursor-pointer hover:bg-primary/5 transition-all ring-1 ring-on-surface/5" onClick={() => setActiveTab('keys')}>
                                            <Key className="w-5 h-5 text-primary" />
                                        </div>
                                        <div className="space-y-0.5">
                                            <h4 className="text-lg font-bold tracking-tight text-on-surface">API Key</h4>
                                            <p className="text-xs font-medium text-on-surface-variant/40 max-w-lg">Generate an API key from the API Keys tab and use it in your identity provider.</p>
                                        </div>
                                    </div>
                                    <Button onClick={() => setActiveTab('keys')} className="h-9 bg-primary text-primary-foreground rounded-xl font-bold text-[11px] px-6 transition-all shadow-lg shadow-primary/20">
                                        Go to API Keys
                                    </Button>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-4">
                                <div className="space-y-6">
                                    <div className="flex items-center gap-4 border-b border-emerald-500/20 pb-3">
                                        <div className="h-7 w-7 bg-success-subtle rounded-lg flex items-center justify-center text-success font-bold text-[10px] ring-1 ring-emerald-500/20 shadow-sm">AZ</div>
                                        <h4 className="text-lg font-bold tracking-tight text-on-surface">Azure AD Setup</h4>
                                    </div>
                                    <ul className="space-y-3">
                                        {[
                                            "Navigate to Enterprise Applications.",
                                            "Click 'Create your own application'.",
                                            "Select 'Non-gallery integration'.",
                                            "Set provisioning mode to Automated.",
                                            "Paste the SCIM URL into the Tenant URL field.",
                                            "Paste your API Key into the Secret Token field.",
                                            "Test the connection and save."
                                        ].map((step, i) => (
                                            <li key={i} className="flex gap-3 group">
                                                <span className="font-mono text-success/40 font-bold text-[10px] group-hover:text-success transition-colors">0{i + 1}</span>
                                                <span className="text-xs font-medium text-on-surface-variant/60 group-hover:text-on-surface group-hover:translate-x-1 transition-all">{step}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>

                                <div className="space-y-6">
                                    <div className="flex items-center gap-4 border-b border-primary/20 pb-3">
                                        <div className="h-7 w-7 bg-primary/5 rounded-lg flex items-center justify-center text-primary font-bold text-[10px] ring-1 ring-primary/20 shadow-sm">OK</div>
                                        <h4 className="text-lg font-bold tracking-tight text-on-surface">Okta Setup</h4>
                                    </div>
                                    <ul className="space-y-3">
                                        {[
                                            "Navigate to Applications dashboard.",
                                            "Create a new SCIM integration.",
                                            "Enable Provisioning settings.",
                                            "Set authentication to HTTP Header.",
                                            "Paste the SCIM URL into the Base URL field.",
                                            "Paste your API Key into the API Token field.",
                                            "Test the connection and save."
                                        ].map((step, i) => (
                                            <li key={i} className="flex gap-3 group">
                                                <span className="font-mono text-primary/40 font-bold text-[10px] group-hover:text-primary transition-colors">0{i + 1}</span>
                                                <span className="text-xs font-medium text-on-surface-variant/60 group-hover:text-on-surface group-hover:translate-x-1 transition-all">{step}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            </div>
                        </GlassCardContent>
                    </GlassCard>
                </TabsContent>
            </Tabs>

            {/* OVERLAYS: MODALS IN BRUTALIST STYLE */}

            {/* Quickstart Overlay */}
            {quickstartApp && (
                <div className="fixed inset-0 z-[200] flex items-center justify-center p-6 bg-on-surface/20 backdrop-blur-md animate-in fade-in duration-300">
                    <GlassCard className="w-full max-w-2xl border-none shadow-2xl overflow-hidden rounded-xl scale-in-center bg-card">
                        <GlassCardHeader className="bg-surface-container p-6 relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-8 opacity-[0.03]">
                                <Terminal className="w-24 h-24" />
                            </div>
                            <div className="relative z-10 flex items-center justify-between">
                                <div>
                                    <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface leading-tight">Application Quickstart</GlassCardTitle>
                                    <p className="text-primary font-bold tracking-tight text-[10px] mt-2">App: {quickstartApp.name}</p>
                                </div>
                                <Button
                                    variant="ghost"
                                    className="h-9 w-9 rounded-xl bg-card shadow-sm ring-1 ring-on-surface/5 hover:bg-destructive/10 hover:text-destructive transition-all"
                                    onClick={() => setQuickstartApp(null)}
                                >
                                    <X className="h-4 w-4" />
                                </Button>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-6 space-y-6 overflow-y-auto max-h-[60vh] custom-scrollbar bg-card">
                            <div className="grid gap-6 md:grid-cols-2">
                                <div className="space-y-2">
                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Issuer URL</Label>
                                    <div className="bg-surface-container/30 ring-1 ring-on-surface/5 rounded-xl p-3 font-mono text-[9px] text-on-surface truncate">{currentIssuerBaseURL}</div>
                                </div>
                                <div className="space-y-2">
                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Client ID</Label>
                                    <div className="bg-surface-container/30 ring-1 ring-on-surface/5 rounded-xl p-3 font-mono text-[9px] text-on-surface truncate">{quickstartApp.client_id}</div>
                                </div>
                            </div>

                            <div className="space-y-3">
                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Environment Variables (.env)</Label>
                                <div className="bg-on-surface text-primary-foreground p-6 font-mono text-[10px] rounded-xl relative group leading-relaxed">
                                    {getQuickstartSnippet(quickstartApp)}
                                    <Button
                                        variant="ghost"
                                        className="absolute top-2 right-2 text-on-inverse/40 hover:text-white hover:bg-card/10 opacity-0 group-hover:opacity-100 transition-all rounded-lg h-7 w-7 p-0"
                                        onClick={() => handleCopyValue('Quickstart snippet', getQuickstartSnippet(quickstartApp))}
                                    >
                                        <Copy className="h-3.5 w-3.5" />
                                    </Button>
                                </div>
                            </div>

                            <div className="space-y-3">
                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Redirect URIs</Label>
                                <div className="space-y-2">
                                    {(quickstartApp.redirect_uris || []).map((uri, index) => (
                                        <div key={index} className="flex gap-2">
                                            <div className="flex-1 bg-surface-container/30 ring-1 ring-on-surface/5 rounded-xl p-2.5 font-mono text-[9px] text-on-surface truncate">{uri}</div>
                                            <Button variant="ghost" className="h-9 w-9 rounded-xl bg-surface-container/50 p-0 group flex items-center justify-center hover:bg-primary hover:text-primary-foreground transition-all shadow-sm" onClick={() => handleCopyValue(`URI ${index + 1}`, uri)}>
                                                <Copy className="h-3.5 w-3.5 opacity-40 group-hover:opacity-100" />
                                            </Button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </GlassCardContent>
                        <div className="bg-surface-container p-6 flex justify-end">
                            <Button className="bg-primary text-primary-foreground rounded-xl font-bold text-[11px] px-8 h-9 shadow-lg shadow-primary/20 transition-all" onClick={() => setQuickstartApp(null)}>Done</Button>
                        </div>
                    </GlassCard>
                </div>
            )}

            {/* Edit App Overlay */}
            {editAppOpen && editingApp && (
                <div className="fixed inset-0 z-[200] flex items-center justify-center p-6 bg-on-surface/20 backdrop-blur-md animate-in fade-in duration-300">
                    <GlassCard className="w-full max-w-2xl border-none shadow-2xl overflow-hidden rounded-xl scale-in-center bg-card">
                        <GlassCardHeader className="bg-surface-container p-6">
                            <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">Edit Application</GlassCardTitle>
                            <p className="text-on-surface-variant/60 font-medium text-[10px] uppercase tracking-widest mt-1">Update settings</p>
                        </GlassCardHeader>
                        <GlassCardContent className="p-6 space-y-6 overflow-y-auto max-h-[60vh] custom-scrollbar bg-card">
                            <form id="edit-app-form" onSubmit={handleUpdateApp} className="space-y-6">
                                <div className="space-y-2">
                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Application Name</Label>
                                    <Input value={editingApp.name} onChange={(e) => setEditingApp({ ...editingApp, name: e.target.value })} required className="h-9 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-bold px-4" />
                                </div>
                                <div className="space-y-2">
                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Description</Label>
                                    <Input value={editingApp.description} onChange={(e) => setEditingApp({ ...editingApp, description: e.target.value })} className="h-9 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium text-xs px-4" />
                                </div>
                                <div className="space-y-2">
                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Redirect URIs</Label>
                                    <Input value={editingApp.redirect_uris} onChange={(e) => setEditingApp({ ...editingApp, redirect_uris: e.target.value })} className="h-9 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-mono text-[10px] px-4" />
                                </div>
                                <div className="grid grid-cols-2 gap-6">
                                    <div className="space-y-2">
                                        <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Application Type</Label>
                                        <select
                                            className="flex h-9 w-full rounded-xl border-none bg-surface-container/30 px-4 font-bold text-xs ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 outline-none appearance-none"
                                            value={editingApp.app_type}
                                            onChange={(e) => setEditingApp({ ...editingApp, app_type: e.target.value })}
                                        >
                                            <option value="web">Web Application</option>
                                            <option value="spa">Single Page App</option>
                                            <option value="native">Native Mobile</option>
                                            <option value="machine">Machine to Machine</option>
                                        </select>
                                    </div>
                                    <div className="space-y-2">
                                        <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">App ID</Label>
                                        <div className="h-9 flex items-center px-4 bg-surface-container/50 rounded-xl font-mono text-[9px] text-on-surface truncate ring-1 ring-on-surface/5">{editingApp.id}</div>
                                    </div>
                                </div>
                            </form>
                        </GlassCardContent>
                        <div className="bg-surface-container p-4 flex justify-between items-center">
                            <Button variant="ghost" className="text-on-surface-variant/40 hover:text-on-surface rounded-xl font-bold text-[10px] uppercase tracking-wider px-6" onClick={() => { setEditAppOpen(false); setEditingApp(null); }}>Cancel</Button>
                            <Button type="submit" form="edit-app-form" className="bg-primary text-primary-foreground rounded-xl font-bold text-[11px] px-8 h-9 shadow-lg shadow-primary/20 transition-all">Save Changes</Button>
                        </div>
                    </GlassCard>
                </div>
            )}

            {/* Assignments Overlay */}
            {assignmentsOpen && selectedAppAssignments && (
                <div className="fixed inset-0 z-[200] flex items-center justify-center p-6 bg-on-surface/20 backdrop-blur-md animate-in fade-in duration-300">
                    <GlassCard className="w-full max-w-xl border-none shadow-2xl overflow-hidden rounded-xl scale-in-center bg-card">
                        <GlassCardHeader className="bg-surface-container p-6 relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-6 opacity-[0.03]">
                                <Users className="w-24 h-24" />
                            </div>
                            <div className="relative z-10 space-y-2">
                                <div className="flex items-center gap-3">
                                    <Badge className="bg-primary/10 text-primary rounded-lg h-6 font-bold text-[9px] tracking-tight px-2.5 border-none">Access Control</Badge>
                                </div>
                                <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface leading-tight">User Permissions</GlassCardTitle>
                                <p className="text-on-surface-variant/60 font-medium text-xs mt-2">App: {selectedAppAssignments.name}</p>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-6 space-y-6 bg-card">
                            <form onSubmit={handleAssignUser} className="flex gap-2">
                                <div className="relative flex-1 group">
                                    <Input
                                        placeholder="Enter User ID or Email..."
                                        value={newAssignUser}
                                        onChange={(e) => setNewAssignUser(e.target.value)}
                                        required
                                        className="h-10 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-bold px-4 pl-10"
                                    />
                                    <UserPlus className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 opacity-20 group-focus-within:opacity-100 transition-opacity text-primary" />
                                </div>
                                <Button type="submit" className="h-10 bg-primary text-primary-foreground rounded-xl font-bold text-[11px] px-6 shadow-lg shadow-primary/20 transition-all">
                                    Add User
                                </Button>
                            </form>

                            <div className="space-y-6">
                                <div className="flex justify-between items-center border-b border-on-surface/5 pb-4">
                                    <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Assigned Users</span>
                                    <Badge className="rounded-xl bg-surface-container/50 text-on-surface-variant/60 font-bold text-[11px] px-4 h-7 border-none">{assignedUsers.length} Users</Badge>
                                </div>

                                <div className="max-h-[40vh] overflow-y-auto space-y-3 custom-scrollbar pr-2">
                                    {assignmentsLoading ? (
                                        <div className="py-20 text-center"><Loader2 className="h-10 w-10 animate-spin mx-auto opacity-20" /></div>
                                    ) : assignedUsers.length === 0 ? (
                                        <div className="py-20 text-center text-sm font-medium text-on-surface-variant/20 italic">No users have been assigned to this application.</div>
                                    ) : assignedUsers.map(user => (
                                        <div key={user} className="flex justify-between items-center p-3 bg-card ring-1 ring-on-surface/5 rounded-xl hover:ring-primary/20 hover:bg-primary/5 transition-all shadow-sm group">
                                            <div className="flex items-center gap-3">
                                                <div className="h-8 w-8 bg-surface-container/50 rounded-lg flex items-center justify-center p-2 group-hover:bg-primary/10 transition-all">
                                                    <Activity className="h-4 w-4 text-on-surface-variant/40 group-hover:text-primary" />
                                                </div>
                                                <span className="font-mono text-[10px] font-bold text-on-surface/80 group-hover:text-primary transition-colors">{user}</span>
                                            </div>
                                            <Button variant="ghost" size="sm" className="h-8 rounded-lg hover:bg-destructive/10 hover:text-destructive text-destructive font-bold uppercase text-[9px] tracking-widest transition-all px-3" onClick={() => handleUnassignUser(user)}>
                                                Revoke
                                            </Button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </GlassCardContent>
                        <div className="bg-surface-container p-4 flex justify-end">
                            <Button className="bg-card text-on-surface rounded-xl font-bold text-[11px] px-8 h-9 shadow-sm ring-1 ring-on-surface/5 hover:ring-on-surface/10 transition-all" onClick={() => setAssignmentsOpen(false)}>Done</Button>
                        </div>
                    </GlassCard>
                </div>
            )}

            {/* Logs Overlay */}
            {logsOpen && selectedLogApp && (
                <div className="fixed inset-0 z-[200] flex items-center justify-center p-6 bg-on-surface/20 backdrop-blur-md animate-in fade-in duration-300">
                    <GlassCard className="w-full max-w-5xl border-none shadow-2xl overflow-hidden rounded-xl scale-in-center bg-card h-[90vh] flex flex-col">
                        <GlassCardHeader className="bg-surface-container p-6 relative overflow-hidden shrink-0">
                            <div className="absolute top-0 right-0 p-6 opacity-[0.02]">
                                <Activity className="w-32 h-32" />
                            </div>
                            <div className="relative z-10 flex items-center justify-between">
                                <div className="space-y-2">
                                    <div className="flex items-center gap-3">
                                        <Badge className="bg-primary/10 text-primary rounded-lg h-6 font-bold text-[9px] tracking-tight px-2.5 border-none">App Activity</Badge>
                                    </div>
                                    <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface leading-tight">Audit Logs</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-bold tracking-tight text-[9px] mt-1">App: {selectedLogApp.name} // Type: {selectedLogApp.type}</p>
                                </div>
                                <Button
                                    variant="ghost"
                                    className="h-9 w-9 rounded-xl bg-card shadow-sm ring-1 ring-on-surface/5 hover:bg-destructive/10 hover:text-destructive transition-all"
                                    onClick={() => setLogsOpen(false)}
                                >
                                    <X className="h-5 w-5" />
                                </Button>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-0 flex flex-col flex-1 overflow-hidden bg-card">
                            <div className="overflow-y-auto flex-1 custom-scrollbar">
                                {logsLoading ? (
                                    <div className="py-40 flex justify-center"><Loader2 className="h-12 w-12 animate-spin text-primary opacity-20" /></div>
                                ) : viewingLogs.length === 0 ? (
                                    <div className="py-40 text-center text-sm font-medium text-on-surface-variant/20 italic">No activity found for this application.</div>
                                ) : (
                                    <div className="divide-y divide-on-surface/5">
                                        {viewingLogs.map((log) => (
                                            <div key={log.id} className="group">
                                                <div
                                                    className="flex items-center justify-between p-4 hover:bg-surface-container/20 cursor-pointer transition-all"
                                                    onClick={() => setExpandedLogId(expandedLogId === log.id ? null : log.id)}
                                                >
                                                    <div className="flex items-center gap-6">
                                                        <div className={`w-12 h-8 flex items-center justify-center font-bold text-[10px] rounded-lg shadow-sm ring-1 ring-on-surface/5 ${log.status_code >= 400 ? 'bg-destructive/10 text-destructive' : 'bg-success-subtle text-success'}`}>
                                                            {log.status_code}
                                                        </div>
                                                        <div className="w-16 text-sm font-bold tracking-tight group-hover:text-primary transition-colors">{log.method}</div>
                                                        <div className="font-mono text-[10px] text-on-surface-variant/40 max-w-[300px] truncate">{log.path}</div>
                                                    </div>
                                                    <div className="flex items-center gap-6 text-[9px] font-bold uppercase tracking-widest text-on-surface-variant/40">
                                                        <div className="flex items-center gap-1.5"><Zap className="h-3 w-3 opacity-40" /> {log.latency_ms}ms</div>
                                                        <div className="flex items-center gap-1.5"><ArrowUpRight className="h-3 w-3 opacity-40" /> {new Date(log.created_at).toLocaleTimeString()}</div>
                                                    </div>
                                                </div>

                                                {expandedLogId === log.id && (
                                                    <div className="p-6 bg-surface-container/10 border-t border-on-surface/5 grid grid-cols-1 lg:grid-cols-2 gap-6 animate-in slide-in-from-top-2 duration-300">
                                                        <div className="space-y-3 flex flex-col h-[400px]">
                                                            <div className="flex items-center justify-between border-b border-on-surface/5 pb-2 ml-1">
                                                                <h4 className="text-[10px] font-bold tracking-tight text-on-surface-variant/40">Request Data</h4>
                                                                <Badge className="bg-on-surface/5 text-on-surface-variant/40 rounded-md text-[8px] font-bold px-1.5 h-5 border-none">Struct v1</Badge>
                                                            </div>
                                                            <div className="bg-on-surface text-primary p-6 rounded-xl font-mono text-[9px] whitespace-pre-wrap overflow-auto flex-1 shadow-2xl ring-1 ring-on-inverse/10 custom-scrollbar leading-relaxed">
                                                                {log.request_payload ? JSON.stringify(JSON.parse(log.request_payload), null, 4) : '{}'}
                                                            </div>
                                                        </div>
                                                        <div className="space-y-3 flex flex-col h-[400px]">
                                                            <div className="flex items-center justify-between border-b border-on-surface/5 pb-2 ml-1">
                                                                <h4 className="text-[10px] font-bold tracking-tight text-on-surface-variant/40">Response Data</h4>
                                                                <Badge className="bg-success/10 text-success rounded-md text-[8px] font-bold px-1.5 h-5 border-none">JSON v1</Badge>
                                                            </div>
                                                            <div className="bg-on-surface text-emerald-400 p-6 rounded-xl font-mono text-[9px] whitespace-pre-wrap overflow-auto flex-1 shadow-2xl ring-1 ring-on-inverse/10 custom-scrollbar leading-relaxed">
                                                                {log.response_payload ? JSON.stringify(JSON.parse(log.response_payload), null, 4) : '{}'}
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </GlassCardContent>
                        <div className="bg-surface-container p-6 flex justify-between items-center shrink-0 border-t border-on-surface/5">
                            <div className="flex items-center gap-3 text-on-surface-variant/40">
                                <Terminal className="w-4 h-4 opacity-40" />
                                <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/40">Logs are stored for 72 hours.</span>
                            </div>
                            <Button className="bg-primary text-primary-foreground rounded-xl font-bold text-[11px] px-8 h-9 shadow-lg shadow-primary/20 transition-all" onClick={() => setLogsOpen(false)}>Done</Button>
                        </div>
                    </GlassCard>
                </div>
            )}
        </div>
        </PageLayout>
    );
};

export default DeveloperApps;
