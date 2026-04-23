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
    SAMLServiceProvider,
    App as AppType
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
    GlassCardDescription
} from '@/components/layout';
import { TableBody, TableCell } from '@/components/ui/table';

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
        <div className="space-y-10 animate-in fade-in duration-700">
            <PageHeader
                icon={<Code2 className="w-8 h-8 text-primary" />}
                title="Developer infrastructure"
                description="Orchestrate OAuth2 clients, API credentials, and identity propagation vectors. Manage the secure integration perimeter for external consumption."
            />

            {/* Secret/Key Alerts: MODERNIST */}
            {(createdSecret || createdAPIKey) && (
                <div className="bg-emerald-50 ring-1 ring-emerald-500/20 p-10 rounded-[32px] relative overflow-hidden group animate-in slide-in-from-top-4">
                    <div className="absolute top-0 right-0 p-8 opacity-5">
                        <Lock className="w-32 h-32 text-emerald-900" />
                    </div>
                    <div className="relative z-10 flex flex-col md:flex-row items-center gap-10">
                        <div className="p-4 bg-white rounded-2xl shadow-sm">
                            <ShieldCheck className="h-10 w-10 text-emerald-600" />
                        </div>
                        <div className="flex-1 space-y-4">
                            <h4 className="text-2xl font-bold tracking-tight text-emerald-900">Credential manifested</h4>
                            <p className="text-[12px] font-semibold text-emerald-900/40 max-w-2xl">
                                Persistent string created successfully. For security reasons, the plain-text value is only revealed once at creation time.
                            </p>
                            <div className="bg-white/50 backdrop-blur-sm p-6 font-mono text-sm break-all rounded-2xl ring-1 ring-emerald-500/10 flex items-center justify-between">
                                <span className="text-emerald-950 font-bold tracking-tight">{createdSecret || createdAPIKey}</span>
                                <Button
                                    variant="ghost"
                                    size="icon"
                                    className="ml-4 hover:bg-emerald-500/10"
                                    onClick={() => handleCopyValue('Credential', createdSecret || createdAPIKey || '')}
                                >
                                    <Copy className="h-4 w-4" />
                                </Button>
                            </div>
                            <Button
                                className="bg-emerald-600 text-white rounded-xl font-bold text-xs px-10 h-11 hover:bg-emerald-700 shadow-lg shadow-emerald-600/10"
                                onClick={() => { setCreatedSecret(null); setCreatedAPIKey(null); }}
                            >
                                Secure Credential
                            </Button>
                        </div>
                    </div>
                </div>
            )}

            {/* Success/Error Alerts */}
            {successMessage && (
                <div className="bg-emerald-50 ring-1 ring-emerald-500/20 rounded-2xl p-5 text-emerald-700 font-bold text-[12px] tracking-tight flex items-center gap-3">
                    <div className="p-1 bg-emerald-500/10 rounded-lg">
                        <Check className="h-3.5 w-3.5 text-emerald-600" />
                    </div>
                    {successMessage}
                </div>
            )}
            {error && (
                <div className="bg-red-50 ring-1 ring-red-500/20 rounded-2xl p-5 text-red-700 font-bold text-[12px] tracking-tight flex items-center gap-3">
                    <div className="p-1 bg-red-500/10 rounded-lg">
                        <AlertTriangle className="h-3.5 w-3.5 text-red-600" />
                    </div>
                    {error}
                </div>
            )}

            {/* TABS: CLEAN MODERNIST */}
            <Tabs defaultValue="apps" className="w-full" onValueChange={setActiveTab}>
                <TabsList className="h-auto p-1.5 bg-surface-container/50 rounded-[24px] ring-1 ring-on-surface/5 flex flex-wrap gap-1 mb-10">
                    <TabsTrigger
                        value="apps"
                        className="h-12 px-8 rounded-xl data-[state=active]:bg-white data-[state=active]:text-primary data-[state=active]:shadow-sm font-bold text-[11px] tracking-tight transition-all text-on-surface-variant/40 hover:text-on-surface"
                    >
                        <Smartphone className="mr-2 h-3.5 w-3.5" /> OAuth Apps
                    </TabsTrigger>
                    <TabsTrigger
                        value="keys"
                        className="h-12 px-8 rounded-xl data-[state=active]:bg-white data-[state=active]:text-primary data-[state=active]:shadow-sm font-bold text-[11px] tracking-tight transition-all text-on-surface-variant/40 hover:text-on-surface"
                    >
                        <Key className="mr-2 h-3.5 w-3.5" /> API Keys
                    </TabsTrigger>
                    <TabsTrigger
                        value="idp"
                        className="h-12 px-8 rounded-xl data-[state=active]:bg-white data-[state=active]:text-primary data-[state=active]:shadow-sm font-bold text-[11px] tracking-tight transition-all text-on-surface-variant/40 hover:text-on-surface"
                    >
                        <Shield className="mr-2 h-3.5 w-3.5" /> IdP Perimeter
                    </TabsTrigger>
                    <TabsTrigger
                        value="scim"
                        className="h-12 px-8 rounded-xl data-[state=active]:bg-white data-[state=active]:text-primary data-[state=active]:shadow-sm font-bold text-[11px] tracking-tight transition-all text-on-surface-variant/40 hover:text-on-surface"
                    >
                        <RefreshCw className="mr-2 h-3.5 w-3.5" /> Directory Sync
                    </TabsTrigger>
                </TabsList>

                {/* OAuth Apps Content */}
                <TabsContent value="apps" className="space-y-10 animate-in fade-in duration-500">
                    <div className="flex justify-between items-center bg-white rounded-[24px] p-8 shadow-xl shadow-on-surface/5 ring-1 ring-on-surface/5">
                        <div className="flex items-center gap-5">
                            <div className="p-3.5 bg-primary/10 rounded-2xl">
                                <Zap className="w-6 h-6 text-primary" />
                            </div>
                        <div className="flex flex-col">
                                <span className="text-on-surface font-bold text-lg tracking-tight leading-none">Resource Provisioning</span>
                                <span className="text-on-surface-variant/40 font-semibold text-[12px] mt-1 tracking-tight">Awaiting registration handshake</span>
                            </div>
                        </div>
                        <Button
                            onClick={() => setCreateAppOpen(!createAppOpen)}
                            className="bg-primary text-white rounded-xl font-bold text-sm px-8 h-12 shadow-lg shadow-primary/10"
                        >
                            {createAppOpen ? 'Abort' : <><Plus className="mr-2 h-4.5 w-4.5" /> Register App</>}
                        </Button>
                    </div>

                    {createAppOpen && (
                        <GlassCard className="border-none shadow-2xl shadow-on-surface/5 overflow-hidden rounded-[32px] scale-in-center bg-white">
                            <GlassCardHeader className="bg-surface-container p-12">
                                <GlassCardTitle className="text-4xl font-bold tracking-tight text-on-surface">Register Entity</GlassCardTitle>
                                <p className="text-on-surface-variant/60 font-medium text-sm mt-3">OAuth2 client registration manifest</p>
                            </GlassCardHeader>
                            <GlassCardContent className="p-12 space-y-12">
                                <form onSubmit={handleCreateApp} className="space-y-10">
                                    <div className="grid gap-10 md:grid-cols-2">
                                        <div className="space-y-2.5">
                                            <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Entity Name</Label>
                                            <Input
                                                placeholder="e.g. CORE_SERVICE"
                                                value={newApp.name}
                                                onChange={(e) => setNewApp({ ...newApp, name: e.target.value })}
                                                required
                                                className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium p-6"
                                            />
                                        </div>
                                        <div className="space-y-2.5">
                                            <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Vector Type</Label>
                                            <select
                                                className="flex h-12 w-full rounded-xl border-none bg-surface-container/30 px-6 font-medium text-sm ring-1 ring-on-surface/5 outline-none focus-visible:ring-2 focus-visible:ring-primary/20 transition-all appearance-none"
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
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Redirect Manifest URLs (CSV)</Label>
                                        <Input
                                            placeholder="https://app.domain/callback"
                                            value={newApp.redirect_uris}
                                            onChange={(e) => setNewApp({ ...newApp, redirect_uris: e.target.value })}
                                            className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-mono text-sm p-6"
                                        />
                                    </div>

                                    <div className="grid gap-10 md:grid-cols-2">
                                        <div className="space-y-4">
                                            <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Authorized Scopes</Label>
                                            <div className="grid grid-cols-2 gap-3">
                                                {AVAILABLE_SCOPES.map(scope => (
                                                    <label key={scope} className={`flex items-center gap-3 p-4 rounded-2xl cursor-pointer transition-all ring-1 ${newApp.scopes.includes(scope) ? 'bg-primary/5 ring-primary/20' : 'bg-surface-container/10 ring-on-surface/5 hover:ring-on-surface/10'}`}>
                                                        <input
                                                            type="checkbox"
                                                            checked={newApp.scopes.includes(scope)}
                                                            onChange={() => toggleScope('new', scope)}
                                                            className="h-4.5 w-4.5 rounded-lg border-on-surface/20 text-primary focus:ring-primary/20"
                                                        />
                                                        <span className="text-[12px] font-bold tracking-tight text-on-surface/60">{scope}</span>
                                                    </label>
                                                ))}
                                            </div>
                                        </div>
                                        <div className="space-y-4">
                                            <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Grant Flows</Label>
                                            <div className="space-y-3">
                                                {AVAILABLE_GRANT_TYPES.map(grantType => (
                                                    <label key={grantType} className={`flex items-center gap-3 p-4 rounded-2xl cursor-pointer transition-all ring-1 ${newApp.grant_types.includes(grantType) ? 'bg-primary/5 ring-primary/20 text-primary' : 'bg-surface-container/10 ring-on-surface/5 hover:ring-on-surface/10 text-on-surface/60'}`}>
                                                        <input
                                                            type="checkbox"
                                                            checked={newApp.grant_types.includes(grantType)}
                                                            onChange={() => toggleGrantType('new', grantType)}
                                                            className="h-4.5 w-4.5 rounded-lg border-on-surface/20 text-primary focus:ring-primary/20"
                                                        />
                                                        <span className="text-[12px] font-bold tracking-tight">{grantType.replace('_', ' ')}</span>
                                                    </label>
                                                ))}
                                            </div>
                                        </div>
                                    </div>

                                    <Button type="submit" className="w-full h-14 rounded-2xl font-bold text-[15px] tracking-tight shadow-xl shadow-primary/20">
                                        Finalize Registration
                                    </Button>
                                </form>
                            </GlassCardContent>
                        </GlassCard>
                    )}

                    {/* APPS GRID: MODERNIST CARDS */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        {apps.map(app => (
                            <GlassCard key={app.id} className="group border-none shadow-xl shadow-on-surface/5 hover:shadow-2xl hover:shadow-primary/5 transition-all overflow-hidden rounded-[32px] bg-white ring-1 ring-on-surface/5">
                                <GlassCardHeader className="bg-surface-container p-10 relative overflow-hidden">
                                    <div className="absolute top-0 right-0 p-8 opacity-[0.03] transition-transform group-hover:scale-125">
                                        <Box className="w-40 h-40" />
                                    </div>
                                    <div className="relative z-10 flex justify-between items-start">
                                        <div className="space-y-5">
                                            <div className="flex items-center gap-4">
                                                <Badge className="rounded-xl bg-primary/10 text-primary font-bold text-[10px] tracking-tight px-3 border-none h-6">{app.app_type}</Badge>
                                                <span className="text-[11px] font-semibold tracking-tight text-on-surface-variant/40">ID: {app.client_id}</span>
                                            </div>
                                            <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface transition-colors">{app.name}</GlassCardTitle>
                                            <p className="text-sm font-medium text-on-surface-variant/40 line-clamp-1">{app.description || "System protocol manifest established."}</p>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <Button size="icon" variant="ghost" className="h-10 w-10 text-on-surface-variant/40 hover:bg-white hover:text-primary rounded-xl" onClick={() => handleOpenEditApp(app)}>
                                                <Pencil className="h-4.5 w-4.5" />
                                            </Button>
                                            <Button size="icon" variant="ghost" className="h-10 w-10 text-on-surface-variant/40 hover:bg-red-50 hover:text-red-500 rounded-xl" onClick={() => handleDeleteApp(app.id)}>
                                                <Trash2 className="h-4.5 w-4.5" />
                                            </Button>
                                        </div>
                                    </div>
                                </GlassCardHeader>
                                <GlassCardContent className="p-10 space-y-10 bg-white">
                                    <div className="grid grid-cols-2 gap-8 pb-8 border-b border-on-surface/5">
                                        <div>
                                            <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40">Active Scopes</span>
                                            <div className="flex flex-wrap gap-2 mt-4">
                                                {(app.scopes && app.scopes.length > 0 ? app.scopes : ['openid', 'profile', 'email']).map(scope => (
                                                    <span key={scope} className="text-[10px] font-bold tracking-tight px-3 py-1.5 bg-surface-container/50 text-on-surface-variant/60 rounded-lg ring-1 ring-on-surface/5">{scope}</span>
                                                ))}
                                            </div>
                                        </div>
                                        <div>
                                            <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40">Grant Flows</span>
                                            <div className="flex flex-wrap gap-2 mt-4">
                                                {(app.grant_types && app.grant_types.length > 0 ? app.grant_types : ['authorization_code', 'refresh_token']).map(grantType => (
                                                    <span key={grantType} className="text-[10px] font-bold tracking-tight px-3 py-1.5 bg-primary/5 text-primary rounded-lg ring-1 ring-primary/10">{grantType.replace('_', ' ')}</span>
                                                ))}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                                        <Button variant="ghost" className="h-14 rounded-2xl bg-surface-container/30 hover:bg-primary hover:text-white transition-all p-0 flex flex-col justify-center gap-1 group/btn" onClick={() => handleRotateSecret(app.id)}>
                                            <RefreshCw className="h-4 w-4 text-on-surface-variant/40 group-hover/btn:text-white transition-colors" />
                                            <span className="text-[10px] font-bold tracking-tight">Rotate</span>
                                        </Button>
                                        <Button variant="ghost" className="h-14 rounded-2xl bg-surface-container/30 hover:bg-primary hover:text-white transition-all p-0 flex flex-col justify-center gap-1 group/btn" onClick={() => handleManageAssignments(app)}>
                                            <Users className="h-4 w-4 text-on-surface-variant/40 group-hover/btn:text-white transition-colors" />
                                            <span className="text-[10px] font-bold tracking-tight">Assign</span>
                                        </Button>
                                        <Button variant="ghost" className="h-14 rounded-2xl bg-surface-container/30 hover:bg-primary hover:text-white transition-all p-0 flex flex-col justify-center gap-1 group/btn" onClick={() => setQuickstartApp(app)}>
                                            <Terminal className="h-4 w-4 text-on-surface-variant/40 group-hover/btn:text-white transition-colors" />
                                            <span className="text-[10px] font-bold tracking-tight">Setup</span>
                                        </Button>
                                        <Button variant="ghost" className="h-14 rounded-2xl bg-surface-container/30 hover:bg-emerald-500 hover:text-white transition-all p-0 flex flex-col justify-center gap-1 group/btn" onClick={() => handleViewLogs(app.id, app.name, 'app')}>
                                            <Activity className="h-4 w-4 text-on-surface-variant/40 group-hover/btn:text-white transition-colors" />
                                            <span className="text-[10px] font-bold tracking-tight">Logs</span>
                                        </Button>
                                    </div>
                                </GlassCardContent>
                            </GlassCard>
                        ))}
                    </div>
                </TabsContent>

                {/* API Keys Content */}
                <TabsContent value="keys" className="space-y-10 animate-in fade-in duration-500">
                    <div className="flex justify-end">
                        <Button
                            onClick={() => setCreateKeyOpen(!createKeyOpen)}
                            className="bg-primary text-white rounded-xl font-bold text-sm px-10 h-14 shadow-lg shadow-primary/10 transition-all"
                        >
                            {createKeyOpen ? 'Abort' : <><Plus className="mr-2 h-5 w-5" /> Generate Key</>}
                        </Button>
                    </div>

                    {createKeyOpen && (
                        <GlassCard className="max-w-2xl mx-auto border-none shadow-2xl rounded-[32px] bg-white overflow-hidden">
                            <GlassCardHeader className="bg-surface-container p-12">
                                <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface">Credential Orchestration</GlassCardTitle>
                                <GlassCardDescription className="text-sm font-medium text-on-surface-variant/40 mt-2">Generate persistent programmatic access vectors.</GlassCardDescription>
                            </GlassCardHeader>
                            <GlassCardContent className="p-12">
                                <form onSubmit={handleCreateAPIKey} className="space-y-10">
                                    <div className="space-y-2.5">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Key Alias</Label>
                                        <Input
                                            placeholder="PROGRAMMATIC_LABEL"
                                            value={newKeyName}
                                            onChange={(e) => setNewKeyName(e.target.value)}
                                            required
                                            className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium p-6"
                                        />
                                    </div>
                                    <Button type="submit" className="w-full h-14 rounded-2xl font-bold text-[15px] tracking-tight shadow-xl shadow-primary/20">
                                        Generate Key
                                    </Button>
                                </form>
                            </GlassCardContent>
                        </GlassCard>
                    )}

                    <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-white overflow-hidden rounded-[32px]">
                        <GlassCardHeader className="bg-surface-container/30 border-b border-on-surface/5 p-10">
                            <div className="flex items-center gap-6">
                                <div className="p-4 bg-primary/10 rounded-2xl">
                                    <Terminal className="w-8 h-8 text-primary" />
                                </div>
                                <div className="space-y-1">
                                    <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface">Active Keys Registry</GlassCardTitle>
                                    <p className="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant/40">{apiKeys.length} Registered Vectors</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-0">
                            {apiKeys.length === 0 ? (
                                <div className="py-24 text-center text-sm font-medium text-on-surface-variant/20 italic">No keys recorded in the primary directory.</div>
                            ) : (
                                <div className="divide-y divide-on-surface/5">
                                    {apiKeys.map(key => (
                                        <div key={key.id} className="flex items-center justify-between p-10 hover:bg-surface-container/20 transition-all group">
                                            <div className="flex items-center gap-8">
                                                <div className="p-4 rounded-2xl bg-surface-container/50 ring-1 ring-on-surface/5 group-hover:bg-primary/10 group-hover:ring-primary/20 transition-all">
                                                    <Fingerprint className="h-8 w-8 text-on-surface-variant/40 group-hover:text-primary transition-colors" />
                                                </div>
                                                <div className="space-y-2">
                                                    <div className="text-2xl font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors leading-none">{key.name}</div>
                                                    <div className="flex items-center gap-4 text-[11px] font-semibold tracking-tight text-on-surface-variant/40">
                                                        <span className="font-mono bg-surface-container px-2 py-1 rounded-md text-[10px]">{key.key_prefix}...</span>
                                                        <span>• Registered {new Date(key.created_at).toLocaleDateString()}</span>
                                                    </div>
                                                </div>
                                            </div>
                                            <div className="flex gap-3">
                                                <Button variant="ghost" className="h-12 rounded-xl bg-surface-container/50 font-bold text-[11px] tracking-tight hover:bg-primary hover:text-white px-8 transition-all" onClick={() => handleViewLogs(key.id, key.name, 'key')}>
                                                    <Activity className="mr-2 h-4 w-4 opacity-40" /> Logs
                                                </Button>
                                                <Button variant="ghost" className="h-12 rounded-xl bg-surface-container/50 font-bold text-[11px] tracking-tight hover:bg-red-500 hover:text-white px-8 text-red-600 transition-all" onClick={() => handleRevokeKey(key.id)}>
                                                    Terminate
                                                </Button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </GlassCardContent>
                    </GlassCard>
                </TabsContent>

                {/* IdP Settings Content */}
                <TabsContent value="idp" className="space-y-10 animate-in fade-in duration-500">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
                        <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-white rounded-[32px] overflow-hidden ring-1 ring-on-surface/5">
                            <GlassCardHeader className="bg-surface-container p-10 relative overflow-hidden">
                                <div className="absolute top-0 right-0 p-10 opacity-[0.03]">
                                    <Globe className="w-40 h-40" />
                                </div>
                                <div className="relative z-10 space-y-4">
                                    <div className="flex items-center gap-4">
                                        <Badge className="bg-primary/10 text-primary rounded-xl h-7 font-bold text-[10px] tracking-tight px-3 border-none">Active Vector</Badge>
                                        <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40">Discovery OIDC</span>
                                    </div>
                                    <GlassCardTitle className="text-4xl font-bold tracking-tight text-on-surface">OIDC Handshake</GlassCardTitle>
                                    <p className="text-sm font-medium text-on-surface-variant/40">OpenID Connect discovery and metadata endpoint.</p>
                                </div>
                            </GlassCardHeader>
                            <GlassCardContent className="p-10 space-y-10">
                                <div className="space-y-6 flex-1">
                                    <div className="space-y-3">
                                        <Label className="text-[11px] font-bold uppercase tracking-wider text-on-surface-variant/50 ml-1">Discovery Issuer URL</Label>
                                        <div className="flex gap-3">
                                            <Input readOnly value={currentIssuerBaseURL} className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 font-mono text-xs p-6" />
                                            <Button variant="ghost" className="h-12 w-12 rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 p-0 hover:bg-primary hover:text-white transition-all shadow-sm" onClick={() => handleCopyValue('Issuer URL', currentIssuerBaseURL)}>
                                                <Copy className="h-5 w-5" />
                                            </Button>
                                        </div>
                                    </div>
                                    <div className="p-8 bg-primary/5 rounded-[24px] ring-1 ring-primary/10 space-y-4">
                                        <div className="flex items-center gap-3">
                                            <Shield className="h-5 w-5 text-primary" />
                                            <span className="text-[11px] font-bold uppercase tracking-widest text-primary">Protocol Active</span>
                                        </div>
                                        <p className="text-xs font-medium text-on-surface-variant/60 leading-relaxed">
                                            LIBRARIES SHOULD LEVERAGE THE WELL-KNOWN ENDPOINT FOR DYNAMIC PROTOCOL NEGOTIATION.
                                        </p>
                                        <div className="font-mono text-[10px] text-on-surface-variant/40 truncate bg-white/50 p-3 rounded-lg ring-1 ring-on-surface/5">
                                            GET {currentIssuerBaseURL}/.well-known/openid-configuration
                                        </div>
                                    </div>
                                </div>
                            </GlassCardContent>
                        </GlassCard>

                        <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-white rounded-[32px] overflow-hidden ring-1 ring-on-surface/5">
                            <GlassCardHeader className="bg-surface-container p-10 relative overflow-hidden">
                                <div className="absolute top-0 right-0 p-10 opacity-[0.03]">
                                    <ShieldCheck className="w-40 h-40" />
                                </div>
                                <div className="relative z-10 space-y-4">
                                    <div className="flex items-center gap-4">
                                        <Badge className="bg-primary/10 text-primary rounded-xl h-7 font-bold text-[10px] tracking-tight px-3 border-none">Enterprise</Badge>
                                        <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40">SAML 2.0 Identity</span>
                                    </div>
                                    <GlassCardTitle className="text-4xl font-bold tracking-tight text-on-surface">SAML Infrastructure</GlassCardTitle>
                                    <p className="text-sm font-medium text-on-surface-variant/40">XML-based identity assertions and metadata propagation.</p>
                                </div>
                            </GlassCardHeader>
                            <GlassCardContent className="p-10 space-y-10">
                                <div className="space-y-6">
                                    <div className="space-y-3">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Metadata Manifest URL</Label>
                                        <div className="flex gap-3">
                                            <Input readOnly value={`${window.location.origin}/saml/metadata`} className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 font-mono text-xs p-6" />
                                            <Button variant="ghost" className="h-12 w-12 rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 p-0 hover:bg-primary hover:text-white transition-all shadow-sm" onClick={() => handleCopyValue('Metadata URL', `${window.location.origin}/saml/metadata`)}>
                                                <Copy className="h-5 w-5" />
                                            </Button>
                                        </div>
                                    </div>
                                    <div className="space-y-3">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">ACS Point (Assertion Consumer)</Label>
                                        <div className="flex gap-3">
                                            <Input readOnly value={`${window.location.origin}/saml/sso`} className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 font-mono text-xs p-6" />
                                            <Button variant="ghost" className="h-12 w-12 rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 p-0 hover:bg-primary hover:text-white transition-all shadow-sm" onClick={() => handleCopyValue('SSO URL', `${window.location.origin}/saml/sso`)}>
                                                <Copy className="h-5 w-5" />
                                            </Button>
                                        </div>
                                    </div>
                                </div>
                            </GlassCardContent>
                        </GlassCard>
                    </div>

                    {/* SAML SPs Registry */}
                    <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-white rounded-[32px] overflow-hidden ring-1 ring-on-surface/5">
                        <GlassCardHeader className="bg-surface-container p-10 flex flex-row items-center justify-between">
                            <div className="flex items-center gap-6">
                                <div className="p-4 bg-primary rounded-2xl">
                                    <Zap className="w-8 h-8 text-white" />
                                </div>
                                <div className="space-y-1">
                                    <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface">Service Providers</GlassCardTitle>
                                    <p className="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant/40">SAML Registration Perimeter</p>
                                </div>
                            </div>
                            <Button
                                onClick={() => setCreateSAMLOpen(!createSAMLOpen)}
                                className="bg-white text-primary rounded-xl font-bold text-sm px-8 h-12 shadow-sm ring-1 ring-on-surface/5 hover:ring-on-surface/10"
                            >
                                {createSAMLOpen ? 'Abort' : <><Plus className="mr-2 h-4.5 w-4.5" /> Register SP</>}
                            </Button>
                        </GlassCardHeader>
                        <GlassCardContent className="p-0">
                            {createSAMLOpen && (
                                <div className="p-10 border-b border-on-surface/5 bg-surface-container/10 animate-in slide-in-from-top-4 duration-500">
                                    <form onSubmit={handleCreateSAMLProvider} className="space-y-10">
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                                            <div className="space-y-2.5">
                                                <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Entity ID (Issuer)</Label>
                                                <Input
                                                    placeholder="https://sp.provider.com/saml"
                                                    value={newSAMLProvider.entity_id}
                                                    onChange={e => setNewSAMLProvider({ ...newSAMLProvider, entity_id: e.target.value })}
                                                    required
                                                    className="h-12 border-none rounded-xl bg-white ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-mono text-sm p-6"
                                                />
                                            </div>
                                            <div className="space-y-2.5">
                                                <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">ACS URL (Recipient)</Label>
                                                <Input
                                                    placeholder="https://sp.provider.com/saml/acs"
                                                    value={newSAMLProvider.acs_url}
                                                    onChange={e => setNewSAMLProvider({ ...newSAMLProvider, acs_url: e.target.value })}
                                                    required
                                                    className="h-12 border-none rounded-xl bg-white ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-mono text-sm p-6"
                                                />
                                            </div>
                                        </div>

                                        <div className="flex flex-wrap gap-8">
                                            <div className="flex items-center gap-5 p-5 bg-white rounded-2xl ring-1 ring-on-surface/5 shadow-sm">
                                                <Switch
                                                    checked={newSAMLProvider.sign_assertions}
                                                    onCheckedChange={checked => setNewSAMLProvider({ ...newSAMLProvider, sign_assertions: checked })}
                                                    className="data-[state=checked]:bg-emerald-500"
                                                />
                                                <div className="flex flex-col">
                                                    <span className="text-[12px] font-bold tracking-tight text-on-surface">Sign Assertions</span>
                                                    <span className="text-[10px] font-medium text-on-surface-variant/40">Crypto Integrity</span>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-5 p-5 bg-white rounded-2xl ring-1 ring-on-surface/5 shadow-sm">
                                                <Switch
                                                    checked={newSAMLProvider.encrypt_assertions}
                                                    onCheckedChange={checked => setNewSAMLProvider({ ...newSAMLProvider.encrypt_assertions, encrypt_assertions: checked })}
                                                    className="data-[state=checked]:bg-emerald-500"
                                                />
                                                <div className="flex flex-col">
                                                    <span className="text-[12px] font-bold tracking-tight text-on-surface">Encrypt Assertions</span>
                                                    <span className="text-[10px] font-medium text-on-surface-variant/40">Data Privacy</span>
                                                </div>
                                            </div>
                                        </div>

                                        <Button type="submit" className="w-full h-14 rounded-2xl font-bold text-sm shadow-xl shadow-primary/20">
                                            Finalize Handshake
                                        </Button>
                                    </form>
                                </div>
                            )}

                            {samlProviders.length === 0 ? (
                                <div className="py-24 text-center text-sm font-medium text-on-surface-variant/20 italic">No service providers registered.</div>
                            ) : (
                                <div className="divide-y divide-on-surface/5">
                                    {samlProviders.map(sp => (
                                        <div key={sp.entity_id} className="flex flex-col md:flex-row items-center justify-between p-10 hover:bg-surface-container/20 transition-all group">
                                            <div className="flex-1 min-w-0 pr-10 space-y-4">
                                                <div className="flex items-center gap-4">
                                                    <Badge className="bg-on-surface/5 text-on-surface-variant/60 rounded-xl font-bold text-[10px] tracking-tight px-3 border-none">SAML Entity</Badge>
                                                    <div className="h-px w-10 bg-on-surface/5" />
                                                </div>
                                                <div className="text-2xl font-bold tracking-tight text-on-surface truncate leading-none group-hover:text-primary transition-colors">{sp.entity_id}</div>
                                                <div className="font-mono text-[10px] text-on-surface-variant/40 truncate">{sp.acs_url}</div>
                                                <div className="flex gap-3 pt-2">
                                                    <Badge className={`rounded-lg font-bold text-[10px] tracking-tight px-2.5 py-1 border-none ${sp.sign_assertions ? 'bg-emerald-50 text-emerald-600' : 'bg-surface-container text-on-surface-variant/20'}`}>Signed</Badge>
                                                    <Badge className={`rounded-lg font-bold text-[10px] tracking-tight px-2.5 py-1 border-none ${sp.encrypt_assertions ? 'bg-emerald-50 text-emerald-600' : 'bg-surface-container text-on-surface-variant/20'}`}>Encrypted</Badge>
                                                </div>
                                            </div>
                                            <Button variant="ghost" size="icon" className="h-14 w-14 rounded-2xl hover:bg-red-50 hover:text-red-500 transition-all" onClick={() => handleDeleteSAMLProvider(sp.entity_id)}>
                                                <Trash2 className="h-6 w-6" />
                                            </Button>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </GlassCardContent>
                    </GlassCard>
                </TabsContent>

                {/* SCIM Content */}
                <TabsContent value="scim" className="space-y-10 animate-in fade-in duration-500">
                    <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-white rounded-[40px] overflow-hidden ring-1 ring-on-surface/5">
                        <GlassCardHeader className="bg-surface-container p-12 relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-12 opacity-[0.02]">
                                <RefreshCw className="w-48 h-48" />
                            </div>
                            <div className="relative z-10 space-y-6">
                                <div className="flex items-center gap-4">
                                    <Badge className="bg-primary/10 text-primary rounded-xl h-7 font-bold text-[10px] tracking-tight px-4">Automated</Badge>
                                    <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40">Sync Protocol Active</span>
                                </div>
                                <GlassCardTitle className="text-5xl font-bold tracking-tight text-on-surface leading-tight">Directory Inbound</GlassCardTitle>
                                <p className="text-sm font-medium text-on-surface-variant/60 max-w-3xl leading-relaxed">
                                    NATIVE SCIM 2.0 ORCHESTRATION. LEVERAGE UPSTREAM IDENTITY PROVIDERS (AD, OKTA) TO PUSH TRANSFORMATION VECTORS INTO THE CORE KERNEL.
                                </p>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-12 space-y-16">
                            {/* Connection Specs */}
                            <div className="space-y-10">
                                <h3 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 border-b border-on-surface/5 pb-6">Connection Specifications</h3>
                                <div className="grid gap-10 md:grid-cols-2">
                                    <div className="p-10 bg-white ring-1 ring-on-surface/5 rounded-[32px] space-y-4 shadow-sm">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">SCIM Endpoint Vector</Label>
                                        <div className="flex gap-3">
                                            <Input readOnly value={`${window.location.origin}/scim/v2`} className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 font-mono text-xs p-6" />
                                            <Button variant="ghost" className="h-12 w-12 rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 p-0 hover:bg-primary hover:text-white transition-all shadow-sm" onClick={() => handleCopyValue('SCIM URL', `${window.location.origin}/scim/v2`)}>
                                                <Copy className="h-5 w-5" />
                                            </Button>
                                        </div>
                                    </div>
                                    <div className="p-10 bg-white ring-1 ring-on-surface/5 rounded-[32px] space-y-4 shadow-sm">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Authentication Flow</Label>
                                        <div className="h-12 flex items-center px-6 bg-primary/10 rounded-xl text-primary font-bold text-xs tracking-tight ring-1 ring-primary/20">
                                            HTTP Bearer Token (OAuth2)
                                        </div>
                                    </div>
                                </div>
                                <div className="p-10 bg-surface-container/30 rounded-[40px] flex flex-col md:flex-row items-center justify-between gap-10 ring-1 ring-on-surface/5 border-2 border-dashed border-on-surface/5">
                                    <div className="flex items-center gap-8">
                                        <div className="p-4 bg-white rounded-2xl shadow-sm cursor-pointer hover:bg-primary/5 transition-all ring-1 ring-on-surface/5" onClick={() => setActiveTab('keys')}>
                                            <Key className="w-8 h-8 text-primary" />
                                        </div>
                                        <div className="space-y-2">
                                            <h4 className="text-2xl font-bold tracking-tight text-on-surface">Security Handshake Token</h4>
                                            <p className="text-sm font-medium text-on-surface-variant/40 max-w-lg">Generate a secure API key from the Keys Registry and manifest it in the upstream IDP.</p>
                                        </div>
                                    </div>
                                    <Button onClick={() => setActiveTab('keys')} className="h-14 bg-primary text-white rounded-2xl font-bold text-sm px-10 transition-all shadow-lg shadow-primary/20">
                                        Access Key Vault
                                    </Button>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-16 pt-10">
                                <div className="space-y-10">
                                    <div className="flex items-center gap-6 border-b border-emerald-500/20 pb-6">
                                        <div className="h-10 w-10 bg-emerald-50 rounded-xl flex items-center justify-center text-emerald-600 font-bold text-xs ring-1 ring-emerald-500/20 shadow-sm">AZ</div>
                                        <h4 className="text-2xl font-bold tracking-tight text-on-surface">Azure AD Orchestration</h4>
                                    </div>
                                    <ul className="space-y-6">
                                        {[
                                            "Navigate to Enterprise Applications.",
                                            "Execute 'Create your own application'.",
                                            "Select 'Non-gallery integration'.",
                                            "Set provisioning mode to Automated.",
                                            "Inject endpoint vector into Tenant URL.",
                                            "Inject API Key into Secret Token vault.",
                                            "Test Connection + Commit state."
                                        ].map((step, i) => (
                                            <li key={i} className="flex gap-5 group">
                                                <span className="font-mono text-emerald-500/40 font-bold text-xs group-hover:text-emerald-500 transition-colors">0{i + 1}</span>
                                                <span className="text-sm font-medium text-on-surface-variant/60 group-hover:text-on-surface group-hover:translate-x-2 transition-all">{step}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>

                                <div className="space-y-10">
                                    <div className="flex items-center gap-6 border-b border-primary/20 pb-6">
                                        <div className="h-10 w-10 bg-primary/5 rounded-xl flex items-center justify-center text-primary font-bold text-xs ring-1 ring-primary/20 shadow-sm">OK</div>
                                        <h4 className="text-2xl font-bold tracking-tight text-on-surface">Okta Pulse Sync</h4>
                                    </div>
                                    <ul className="space-y-6">
                                        {[
                                            "Navigate to Applications dashboard.",
                                            "Create new integration (SWA Vector).",
                                            "Activate 'Provisioning' data plane.",
                                            "Select HTTP Header handshake.",
                                            "Inject SCIM endpoint into Base URL.",
                                            "Inject API Key into API Token field.",
                                            "Validate Credentials + Save state."
                                        ].map((step, i) => (
                                            <li key={i} className="flex gap-5 group">
                                                <span className="font-mono text-primary/40 font-bold text-xs group-hover:text-primary transition-colors">0{i + 1}</span>
                                                <span className="text-sm font-medium text-on-surface-variant/60 group-hover:text-on-surface group-hover:translate-x-2 transition-all">{step}</span>
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
                    <GlassCard className="w-full max-w-3xl border-none shadow-2xl overflow-hidden rounded-[40px] scale-in-center bg-white">
                        <GlassCardHeader className="bg-surface-container p-12 relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-12 opacity-[0.03]">
                                <Terminal className="w-40 h-40" />
                            </div>
                            <div className="relative z-10 flex items-center justify-between">
                                <div>
                                    <GlassCardTitle className="text-4xl font-bold tracking-tight text-on-surface leading-tight">Quickstart Manifest</GlassCardTitle>
                                    <p className="text-primary font-bold tracking-tight text-[11px] mt-4">Entity: {quickstartApp.name}</p>
                                </div>
                                <Button
                                    variant="ghost"
                                    className="h-12 w-12 rounded-xl bg-white shadow-sm ring-1 ring-on-surface/5 hover:bg-red-50 hover:text-red-500 transition-all"
                                    onClick={() => setQuickstartApp(null)}
                                >
                                    <X className="h-5 w-5" />
                                </Button>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-12 space-y-10 overflow-y-auto max-h-[60vh] custom-scrollbar bg-white">
                            <div className="grid gap-10 md:grid-cols-2">
                                <div className="space-y-2.5">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Issuer Vector</Label>
                                    <div className="bg-surface-container/30 ring-1 ring-on-surface/5 rounded-xl p-4 font-mono text-[10px] text-on-surface truncate">{currentIssuerBaseURL}</div>
                                </div>
                                <div className="space-y-2.5">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Client Identifier</Label>
                                    <div className="bg-surface-container/30 ring-1 ring-on-surface/5 rounded-xl p-4 font-mono text-[10px] text-on-surface truncate">{quickstartApp.client_id}</div>
                                </div>
                            </div>

                            <div className="space-y-4">
                                <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Environment Snippet (.env)</Label>
                                <div className="bg-on-surface text-primary-foreground p-8 font-mono text-[11px] rounded-[24px] relative group leading-relaxed">
                                    {getQuickstartSnippet(quickstartApp)}
                                    <Button
                                        variant="ghost"
                                        className="absolute top-4 right-4 text-white/40 hover:text-white hover:bg-white/10 opacity-0 group-hover:opacity-100 transition-all rounded-lg"
                                        onClick={() => handleCopyValue('Quickstart snippet', getQuickstartSnippet(quickstartApp))}
                                    >
                                        <Copy className="h-4 w-4" />
                                    </Button>
                                </div>
                            </div>

                            <div className="space-y-4">
                                <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Redirect Hands Collection</Label>
                                <div className="space-y-3">
                                    {(quickstartApp.redirect_uris || []).map((uri, index) => (
                                        <div key={index} className="flex gap-3">
                                            <div className="flex-1 bg-surface-container/30 ring-1 ring-on-surface/5 rounded-xl p-3.5 font-mono text-[10px] text-on-surface truncate">{uri}</div>
                                            <Button variant="ghost" className="h-12 w-12 rounded-xl bg-surface-container/50 p-0 group flex items-center justify-center hover:bg-primary hover:text-white transition-all shadow-sm" onClick={() => handleCopyValue(`URI ${index + 1}`, uri)}>
                                                <Copy className="h-4 w-4 opacity-40 group-hover:opacity-100" />
                                            </Button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </GlassCardContent>
                        <div className="bg-surface-container p-10 flex justify-end">
                            <Button className="bg-primary text-white rounded-xl font-bold text-sm px-12 h-12 shadow-lg shadow-primary/20 transition-all" onClick={() => setQuickstartApp(null)}>Dismiss manifest</Button>
                        </div>
                    </GlassCard>
                </div>
            )}

            {/* Edit App Overlay */}
            {editAppOpen && editingApp && (
                <div className="fixed inset-0 z-[200] flex items-center justify-center p-6 bg-on-surface/20 backdrop-blur-md animate-in fade-in duration-300">
                    <GlassCard className="w-full max-w-2xl border-none shadow-2xl overflow-hidden rounded-[40px] scale-in-center bg-white">
                        <GlassCardHeader className="bg-surface-container p-12">
                            <GlassCardTitle className="text-4xl font-bold tracking-tight text-on-surface">Edit Entity</GlassCardTitle>
                            <p className="text-on-surface-variant/60 font-medium text-sm mt-3">Application manifest update</p>
                        </GlassCardHeader>
                        <GlassCardContent className="p-12 space-y-12 overflow-y-auto max-h-[60vh] custom-scrollbar bg-white">
                            <form id="edit-app-form" onSubmit={handleUpdateApp} className="space-y-10">
                                <div className="space-y-2.5">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Entity alias</Label>
                                    <Input value={editingApp.name} onChange={(e) => setEditingApp({ ...editingApp, name: e.target.value })} required className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-bold p-6" />
                                </div>
                                <div className="space-y-2.5">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Entity description</Label>
                                    <Input value={editingApp.description} onChange={(e) => setEditingApp({ ...editingApp, description: e.target.value })} className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium text-sm p-6" />
                                </div>
                                <div className="space-y-2.5">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Redirect manifest URLs</Label>
                                    <Input value={editingApp.redirect_uris} onChange={(e) => setEditingApp({ ...editingApp, redirect_uris: e.target.value })} className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-mono text-xs p-6" />
                                </div>
                                <div className="grid grid-cols-2 gap-10">
                                    <div className="space-y-2.5">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Entity vector type</Label>
                                        <select
                                            className="flex h-12 w-full rounded-xl border-none bg-surface-container/30 px-6 font-bold text-sm ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 outline-none appearance-none"
                                            value={editingApp.app_type}
                                            onChange={(e) => setEditingApp({ ...editingApp, app_type: e.target.value })}
                                        >
                                            <option value="web">Web Application</option>
                                            <option value="spa">Single Page App</option>
                                            <option value="native">Native Mobile</option>
                                            <option value="machine">Machine to Machine</option>
                                        </select>
                                    </div>
                                    <div className="space-y-2.5">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">System identifier</Label>
                                        <div className="h-12 flex items-center px-6 bg-surface-container/50 rounded-xl font-mono text-[10px] text-on-surface truncate ring-1 ring-on-surface/5">{editingApp.id}</div>
                                    </div>
                                </div>
                            </form>
                        </GlassCardContent>
                        <div className="bg-surface-container p-10 flex justify-between items-center">
                            <Button variant="ghost" className="text-on-surface-variant/40 hover:text-on-surface rounded-xl font-bold text-[11px] uppercase tracking-wider px-8" onClick={() => { setEditAppOpen(false); setEditingApp(null); }}>Abort</Button>
                            <Button type="submit" form="edit-app-form" className="bg-primary text-white rounded-xl font-bold text-sm px-12 h-12 shadow-lg shadow-primary/20 transition-all">Commit Attributes</Button>
                        </div>
                    </GlassCard>
                </div>
            )}

            {/* Assignments Overlay */}
            {assignmentsOpen && selectedAppAssignments && (
                <div className="fixed inset-0 z-[200] flex items-center justify-center p-6 bg-on-surface/20 backdrop-blur-md animate-in fade-in duration-300">
                    <GlassCard className="w-full max-w-2xl border-none shadow-2xl overflow-hidden rounded-[40px] scale-in-center bg-white">
                        <GlassCardHeader className="bg-surface-container p-12 relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-12 opacity-[0.03]">
                                <Users className="w-40 h-40" />
                            </div>
                            <div className="relative z-10 space-y-4">
                                <div className="flex items-center gap-4">
                                    <Badge className="bg-primary/10 text-primary rounded-xl h-7 font-bold text-[9px] tracking-tight px-4 border-none">Authorization pivot</Badge>
                                </div>
                                <GlassCardTitle className="text-4xl font-bold tracking-tight text-on-surface leading-tight">Assignee Registry</GlassCardTitle>
                                <p className="text-on-surface-variant/60 font-medium text-sm mt-3">Entity: {selectedAppAssignments.name}</p>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-12 space-y-12 bg-white">
                            <form onSubmit={handleAssignUser} className="flex gap-4">
                                <div className="relative flex-1 group">
                                    <Input
                                        placeholder="Input ID or Email..."
                                        value={newAssignUser}
                                        onChange={(e) => setNewAssignUser(e.target.value)}
                                        required
                                        className="h-14 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-bold p-6 pl-14"
                                    />
                                    <UserPlus className="absolute left-5 top-1/2 -translate-y-1/2 h-5 w-5 opacity-20 group-focus-within:opacity-100 transition-opacity text-primary" />
                                </div>
                                <Button type="submit" className="h-14 bg-primary text-white rounded-xl font-bold text-sm px-10 shadow-lg shadow-primary/20 transition-all">
                                    Grant Access
                                </Button>
                            </form>

                            <div className="space-y-6">
                                <div className="flex justify-between items-center border-b border-on-surface/5 pb-6">
                                    <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Active Subject Lignage</span>
                                    <Badge className="rounded-xl bg-surface-container/50 text-on-surface-variant/60 font-bold text-[11px] px-4 h-7 border-none">{assignedUsers.length} Entities</Badge>
                                </div>

                                <div className="max-h-[40vh] overflow-y-auto space-y-3 custom-scrollbar pr-2">
                                    {assignmentsLoading ? (
                                        <div className="py-20 text-center"><Loader2 className="h-10 w-10 animate-spin mx-auto opacity-20" /></div>
                                    ) : assignedUsers.length === 0 ? (
                                        <div className="py-20 text-center text-sm font-medium text-on-surface-variant/20 italic">No assigned entities identified.</div>
                                    ) : (
                                        assignedUsers.map(user => (
                                            <div key={user} className="flex justify-between items-center p-5 bg-white ring-1 ring-on-surface/5 rounded-2xl hover:ring-primary/20 hover:bg-primary/5 transition-all shadow-sm group">
                                                <div className="flex items-center gap-5">
                                                    <div className="h-10 w-10 bg-surface-container/50 rounded-xl flex items-center justify-center p-2 group-hover:bg-primary/10 transition-all">
                                                        <Activity className="h-5 w-5 text-on-surface-variant/40 group-hover:text-primary" />
                                                    </div>
                                                    <span className="font-mono text-xs font-bold text-on-surface/80 group-hover:text-primary transition-colors">{user}</span>
                                                </div>
                                                <Button variant="ghost" size="sm" className="h-10 rounded-xl hover:bg-red-50 hover:text-red-500 text-red-600 font-bold uppercase text-[10px] tracking-widest transition-all" onClick={() => handleUnassignUser(user)}>
                                                    Revoke
                                                </Button>
                                            </div>
                                        ))
                                    )}
                                </div>
                            </div>
                        </GlassCardContent>
                        <div className="bg-surface-container p-10 flex justify-end">
                            <Button className="bg-white text-on-surface rounded-xl font-bold text-sm px-12 h-12 shadow-sm ring-1 ring-on-surface/5 hover:ring-on-surface/10 transition-all" onClick={() => setAssignmentsOpen(false)}>Close Registry</Button>
                        </div>
                    </GlassCard>
                </div>
            )}

            {/* Logs Overlay */}
            {logsOpen && selectedLogApp && (
                <div className="fixed inset-0 z-[200] flex items-center justify-center p-6 bg-on-surface/20 backdrop-blur-md animate-in fade-in duration-300">
                    <GlassCard className="w-full max-w-5xl border-none shadow-2xl overflow-hidden rounded-[40px] scale-in-center bg-white h-[90vh] flex flex-col">
                        <GlassCardHeader className="bg-surface-container p-12 relative overflow-hidden shrink-0">
                            <div className="absolute top-0 right-0 p-12 opacity-[0.02]">
                                <Activity className="w-60 h-60" />
                            </div>
                            <div className="relative z-10 flex items-center justify-between">
                                <div className="space-y-4">
                                    <div className="flex items-center gap-4">
                                        <Badge className="bg-primary/10 text-primary rounded-xl h-7 font-bold text-[11px] tracking-tight px-4 border-none">Real-time telemetry</Badge>
                                    </div>
                                    <GlassCardTitle className="text-5xl font-bold tracking-tight text-on-surface leading-tight">Forensic signal logs</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-bold tracking-tight text-[11px] mt-2">Target: {selectedLogApp.name} // Type: {selectedLogApp.type}</p>
                                </div>
                                <Button
                                    variant="ghost"
                                    className="h-14 w-14 rounded-2xl bg-white shadow-sm ring-1 ring-on-surface/5 hover:bg-red-50 hover:text-red-500 transition-all"
                                    onClick={() => setLogsOpen(false)}
                                >
                                    <X className="h-8 w-8" />
                                </Button>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-0 flex flex-col flex-1 overflow-hidden bg-white">
                            <div className="overflow-y-auto flex-1 custom-scrollbar">
                                {logsLoading ? (
                                    <div className="py-40 flex justify-center"><Loader2 className="h-12 w-12 animate-spin text-primary opacity-20" /></div>
                                ) : viewingLogs.length === 0 ? (
                                    <div className="py-40 text-center text-sm font-medium text-on-surface-variant/20 italic">No telemetry recorded in this vector.</div>
                                ) : (
                                    <div className="divide-y divide-on-surface/5">
                                        {viewingLogs.map((log) => (
                                            <div key={log.id} className="group">
                                                <div
                                                    className="flex items-center justify-between p-8 hover:bg-surface-container/20 cursor-pointer transition-all"
                                                    onClick={() => setExpandedLogId(expandedLogId === log.id ? null : log.id)}
                                                >
                                                    <div className="flex items-center gap-10">
                                                        <div className={`w-16 h-10 flex items-center justify-center font-bold text-xs rounded-xl shadow-sm ring-1 ring-on-surface/5 ${log.status_code >= 400 ? 'bg-red-50 text-red-600' : 'bg-emerald-50 text-emerald-600'}`}>
                                                            {log.status_code}
                                                        </div>
                                                        <div className="w-20 text-xl font-bold tracking-tight group-hover:text-primary transition-colors">{log.method}</div>
                                                        <div className="font-mono text-sm text-on-surface-variant/40 max-w-[400px] truncate">{log.path}</div>
                                                    </div>
                                                    <div className="flex items-center gap-10 text-[11px] font-bold uppercase tracking-widest text-on-surface-variant/40">
                                                        <div className="flex items-center gap-2"><Zap className="h-3.5 w-3.5 opacity-40" /> {log.latency_ms}ms</div>
                                                        <div className="flex items-center gap-2"><ArrowUpRight className="h-3.5 w-3.5 opacity-40" /> {new Date(log.created_at).toLocaleTimeString()}</div>
                                                    </div>
                                                </div>

                                                {expandedLogId === log.id && (
                                                    <div className="p-10 bg-surface-container/10 border-t border-on-surface/5 grid grid-cols-1 lg:grid-cols-2 gap-10 animate-in slide-in-from-top-2 duration-300">
                                                        <div className="space-y-4 flex flex-col h-[500px]">
                                                            <div className="flex items-center justify-between border-b border-on-surface/5 pb-4 ml-1">
                                                                <h4 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40">Signal Request Payload</h4>
                                                                <Badge className="bg-on-surface/5 text-on-surface-variant/40 rounded-lg text-[10px] font-bold px-2 h-6 border-none">Struct v1</Badge>
                                                            </div>
                                                            <div className="bg-on-surface text-primary p-8 rounded-[32px] font-mono text-[11px] whitespace-pre-wrap overflow-auto flex-1 shadow-2xl ring-1 ring-white/10 custom-scrollbar leading-relaxed">
                                                                {log.request_payload ? JSON.stringify(JSON.parse(log.request_payload), null, 4) : '{}'}
                                                            </div>
                                                        </div>
                                                        <div className="space-y-4 flex flex-col h-[500px]">
                                                            <div className="flex items-center justify-between border-b border-on-surface/5 pb-4 ml-1">
                                                                <h4 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40">Signal Response Payload</h4>
                                                                <Badge className="bg-emerald-500/10 text-emerald-600 rounded-lg text-[10px] font-bold px-2 h-6 border-none">JSON v1</Badge>
                                                            </div>
                                                            <div className="bg-on-surface text-emerald-400 p-8 rounded-[32px] font-mono text-[11px] whitespace-pre-wrap overflow-auto flex-1 shadow-2xl ring-1 ring-white/10 custom-scrollbar leading-relaxed">
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
                        <div className="bg-surface-container p-10 flex justify-between items-center shrink-0 border-t border-on-surface/5">
                            <div className="flex items-center gap-4 text-on-surface-variant/40">
                                <Terminal className="w-5 h-5 opacity-40" />
                                <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/40">Telemetry data plane retention: 72 hours</span>
                            </div>
                            <Button className="bg-primary text-white rounded-xl font-bold text-sm px-12 h-12 shadow-lg shadow-primary/20 transition-all" onClick={() => setLogsOpen(false)}>Dismiss Telemetry</Button>
                        </div>
                    </GlassCard>
                </div>
            )}
        </div>
    );
};

export default DeveloperApps;
