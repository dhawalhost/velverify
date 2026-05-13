import axios from 'axios';

export const AUTHSVC_URL = (import.meta as any).env?.VITE_AUTHSVC_URL || '';
const DIRSVC_URL = (import.meta as any).env?.VITE_DIRSVC_URL || '';
const GOVSVC_URL = (import.meta as any).env?.VITE_GOVSVC_URL || '';

console.log('API Strings:', { AUTHSVC_URL, DIRSVC_URL, GOVSVC_URL });

export const api = axios.create({
    baseURL: AUTHSVC_URL,
    withCredentials: true,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Directory service API (hosts SCIM, user management)
const dirApi = axios.create({
    baseURL: DIRSVC_URL,
    withCredentials: true,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Governance service API (hosts requests, sso, audit, etc)
const govApi = axios.create({
    baseURL: GOVSVC_URL,
    withCredentials: true,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Add interceptor to directory API as well
dirApi.interceptors.request.use(
    (config) => {
        const tenantID = localStorage.getItem('tenantID');
        const userId = localStorage.getItem('userId');
        if (tenantID) {
            config.headers['X-Tenant-ID'] = tenantID;
        }
        if (userId) {
            config.headers['X-User-ID'] = userId;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

// Add interceptor to governance API
govApi.interceptors.request.use(
    (config) => {
        const tenantID = localStorage.getItem('tenantID');
        const userId = localStorage.getItem('userId');
        if (tenantID) {
            config.headers['X-Tenant-ID'] = tenantID;
        }
        if (userId) {
            config.headers['X-User-ID'] = userId;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

// Add a request interceptor to inject metadata
api.interceptors.request.use(
    (config) => {
        const tenantID = localStorage.getItem('tenantID');
        const userId = localStorage.getItem('userId');
        if (tenantID) {
            config.headers['X-Tenant-ID'] = tenantID;
        }
        if (userId) {
            config.headers['X-User-ID'] = userId;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

export const login = async (username: string, password: string, deviceID?: string, osVersion?: string) => {
    const headers: Record<string, string> = {};
    if (deviceID) {
        headers['X-Device-ID'] = deviceID;
    }
    if (osVersion) {
        headers['X-OS-Version'] = osVersion;
    }
    const tenantID = localStorage.getItem('tenantID');
    const tenantSlug = localStorage.getItem('tenantSlug');
    const tenantPath = tenantSlug || tenantID;
    const path = tenantPath ? `/t/${tenantPath}/login` : '/login';
    const response = await api.post(path, { username, password }, { headers });
    return response.data;
};

export const signup = async (email: string, password: string, companyName: string, plan: string = 'free') => {
    const response = await api.post('/api/v1/signup', { email, password, company_name: companyName, plan });
    return response.data;
};

// System Setup
export const logout = async () => {
    const tenantID = localStorage.getItem('tenantID');
    const tenantSlug = localStorage.getItem('tenantSlug');
    const tenantPath = tenantSlug || tenantID;
    const path = tenantPath ? `/t/${tenantPath}/logout` : '/logout';
    await api.post(path);
};
export const getSetupStatus = async () => {
    const response = await api.get('/api/v1/setup/status');
    return response.data;
};

export const performSetup = async (email: string, password: string) => {
    const response = await api.post('/api/v1/setup', { email, password });
    return response.data;
};

export const lookupUser = async (email: string) => {
    const response = await api.post('/login/lookup', { email });
    return response.data;
};

export const completeMfaLogin = async (pendingToken: string, totpCode: string, userId: string) => {
    const tenantID = localStorage.getItem('tenantID');
    const tenantSlug = localStorage.getItem('tenantSlug');
    const tenantPath = tenantSlug || tenantID;
    const path = tenantPath ? `/t/${tenantPath}/login/mfa` : '/login/mfa';
    const response = await api.post(path, {
        pending_token: pendingToken,
        totp_code: totpCode,
        user_id: userId
    });
    return response.data;
};

// WebAuthn
export const beginRegistration = async (userID: string) => {
    // Requires X-User-ID header if not authenticated? Or authenticated context.
    // Our backend expects X-User-ID header for now as per previous implementation logic.
    // But usually registration is done while logged in.
    const response = await api.post('/api/v1/mfa/webauthn/register/begin', {}, {
        headers: { 'X-User-ID': userID }
    });
    return response.data;
};

export const finishRegistration = async (userID: string, data: any) => {
    const response = await api.post('/api/v1/mfa/webauthn/register/finish', data, {
        headers: { 'X-User-ID': userID }
    });
    return response.data;
};

export const beginLogin = async (userID: string) => {
    const response = await api.post('/api/v1/mfa/webauthn/login/begin', { user_id: userID });
    return response.data;
};

export const finishLogin = async (userID: string, data: any) => {
    const response = await api.post(`/api/v1/mfa/webauthn/login/finish?user_id=${userID}`, data);
    return response.data;
};

export const getSCIMUsers = async () => {
    const response = await dirApi.get('/scim/v2/Users');
    return response.data;
};

export const getSCIMUser = async (userId: string) => {
    const response = await dirApi.get(`/scim/v2/Users/${userId}`)
    return response.data;
}

export const updateSCIMUser = async (userId: string, userData: any) => {
    const response = await dirApi.put(`/scim/v2/Users/${userId}`, {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        ...userData
    });
    return response.data;
}

export const createSCIMUser = async (userData: any) => {
    const response = await dirApi.post('/scim/v2/Users', {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        ...userData
    });
    return response.data;
}

export const deleteSCIMUser = async (userId: string) => {
    const response = await dirApi.delete(`/scim/v2/Users/${userId}`);
    return response.data;
}

// SCIM Configuration
export const getSCIMConfig = async () => {
    const response = await dirApi.get('/scim/v2/ServiceProviderConfig');
    return response.data;
};

export const getSCIMSchemas = async () => {
    const response = await dirApi.get('/scim/v2/Schemas');
    return response.data;
};

export const requestPasswordSetupLink = async (userID: string, mode: 'invite' | 'reset', expiresHours: number = 72) => {
    const response = await api.post('/api/v1/setup/password-link', {
        user_id: userID,
        mode,
        expires_hours: expiresHours,
    });
    return response.data;
};

export const completePasswordSetup = async (token: string, password: string) => {
    const response = await api.post('/api/v1/setup/password', { token, password });
    return response.data;
};

// Access Requests
export interface AccessRequest {
    id: string;
    tenant_id: string;
    requester_id: string;
    resource_type: string;
    resource_id: string;
    status: string;
    reason: string;
    duration?: string;
    created_at: string;
    updated_at: string;
}

export const getAccessRequests = async (status?: string) => {
    const params = status ? { status } : {};
    const response = await govApi.get('/api/v1/governance/requests', { params });
    const data = response.data;
    // Handle different response formats if legacy
    return data.requests || data;
};

export const createAccessRequest = async (resourceType: string, resourceID: string, reason: string, duration?: string) => {
    const response = await govApi.post('/api/v1/governance/requests', {
        resource_type: resourceType,
        resource_id: resourceID,
        reason: reason,
        duration: duration
    });
    return response.data;
};

export const approveAccessRequest = async (id: string, comment?: string) => {
    const response = await govApi.post(`/api/v1/governance/requests/${id}/approve`, { comment });
    return response.data;
};

export const rejectAccessRequest = async (id: string, comment?: string) => {
    const response = await govApi.post(`/api/v1/governance/requests/${id}/reject`, { comment });
    return response.data;
};

// IP Policies
export interface IPPolicy {
    id: string;
    tenant_id: string;
    type: 'allow' | 'block';
    cidr: string;
    country_code?: string;
    reason?: string;
    created_at: string;
}

export const getIPPolicies = async () => {
    const response = await govApi.get('/api/v1/governance/ip-policies');
    return response.data.policies;
};

export const createIPPolicy = async (policy: {
    type: 'allow' | 'block';
    cidr?: string;
    country?: string;
    reason?: string;
}) => {
    const response = await govApi.post('/api/v1/governance/ip-policies', policy);
    return response.data;
};

export const deleteIPPolicy = async (id: string) => {
    await govApi.delete(`/api/v1/governance/ip-policies/${id}`);
};

// RBAC - Roles
export const getRoles = async () => {
    const response = await govApi.get('/api/v1/roles');
    return response.data;
};

export const createRole = async (name: string, description: string) => {
    const response = await govApi.post('/api/v1/roles', { name, description });
    return response.data;
};

export const deleteRole = async (id: string) => {
    const response = await govApi.delete(`/api/v1/roles/${id}`);
    return response.data;
};

export const getRolePermissions = async (roleId: string) => {
    const response = await govApi.get(`/api/v1/roles/${roleId}/permissions`);
    return response.data;
};

export const assignPermissionToRole = async (roleId: string, permissionId: string) => {
    // RBAC permissions assignment is on gov/rbac handlers
    const response = await govApi.post(`/api/v1/roles/${roleId}/permissions/${permissionId}`);
    return response.data;
};

// RBAC - Permissions
export const getPermissions = async () => {
    // RBAC permissions list is on gov/rbac handlers
    const response = await govApi.get('/api/v1/permissions');
    return response.data;
};

export const createPermission = async (resource: string, action: string, description: string) => {
    const response = await govApi.post('/api/v1/permissions', { resource, action, description });
    return response.data;
};

// RBAC - User Roles
export const getUserRoles = async (userId: string) => {
    const response = await govApi.get(`/api/v1/users/${userId}/roles`);
    return response.data;
};

export const assignRoleToUser = async (userId: string, roleId: string) => {
    const response = await govApi.post(`/api/v1/users/${userId}/roles/${roleId}`);
    return response.data;
};

export const removeRoleFromUser = async (userId: string, roleId: string) => {
    const response = await govApi.delete(`/api/v1/users/${userId}/roles/${roleId}`);
    return response.data;
};

// Groups
export interface Group {
    id: string;
    tenant_id: string;
    name: string;
    description?: string;
    created_at: string;
    updated_at: string;
}

export const getGroups = async (limit: number = 20, offset: number = 0) => {
    const response = await dirApi.get('/groups', { params: { limit, offset } });
    return response.data;
};

export const getGroupMembers = async (groupId: string) => {
    const response = await dirApi.get(`/groups/${groupId}/users`);
    return response.data.users;
};

export const createGroup = async (group: { name: string; description?: string }) => {
    const response = await dirApi.post('/groups', { group });
    return response.data;
};

export const updateGroup = async (id: string, group: { name: string; description?: string }) => {
    const response = await dirApi.put(`/groups/${id}`, { group });
    return response.data;
};

export const deleteGroup = async (id: string) => {
    await dirApi.delete(`/groups/${id}`);
};

export const addUserToGroup = async (groupId: string, userId: string) => {
    const response = await dirApi.post(`/groups/${groupId}/users`, { user_id: userId });
    return response.data;
};

export const removeUserFromGroup = async (groupId: string, userId: string) => {
    const response = await dirApi.delete(`/groups/${groupId}/users/${userId}`);
    return response.data;
};

// Audit Logs
export const getAuditLogs = async (params?: {
    action?: string;
    resource_type?: string;
    start_time?: string;
    end_time?: string;
    limit?: number;
    offset?: number;
}) => {
    const response = await govApi.get('/api/v1/audit', { params });
    return response.data;
};

export const exportAuditLogs = async (params?: Record<string, unknown>) => {
    const response = await govApi.get('/api/v1/audit/export', {
        params,
        responseType: 'blob'
    });
    return response.data;
};

export const getAuditStats = async (lookbackDays: number = 7) => {
    const response = await govApi.get('/api/v1/audit/stats', {
        params: { lookback_days: lookbackDays }
    });
    return response.data;
};

// Safety Store
export const getSafetyActions = async (status?: string) => {
    const params = status ? { status } : {};
    const response = await govApi.get('/api/v1/safety/actions', { params });
    return response.data;
};

export const confirmSafetyAction = async (id: string, comment: string) => {
    const response = await govApi.post(`/api/v1/safety/actions/${id}/confirm`, { comment });
    return response.data;
};

export const rejectSafetyAction = async (id: string, comment: string) => {
    const response = await govApi.post(`/api/v1/safety/actions/${id}/reject`, { comment });
    return response.data;
};

// Endpoints (Device Trust)
export interface Device {
    id: string;
    tenant_id: string;
    user_id: string;
    serial: string;
    platform: string;
    os_version: string;
    trust_status: 'pending' | 'trusted' | 'untrusted';
    last_scan_at: string;
    created_at: string;
}

export const getEndpoints = async () => {
    const response = await govApi.get('/api/v1/governance/endpoints');
    return response.data.devices;
};

export const updateEndpointStatus = async (id: string, status: string) => {
    const response = await govApi.put(`/api/v1/governance/endpoints/${id}/status`, { status });
    return response.data;
};

// Campaigns
export const getCampaigns = async (status?: string) => {
    const params = status ? { status } : {};
    const response = await govApi.get('/api/v1/campaigns', { params });
    return response.data;
};

export const createCampaign = async (name: string, description: string, reviewerId: string) => {
    const response = await govApi.post('/api/v1/campaigns', {
        name,
        description,
        reviewer_id: reviewerId
    });
    return response.data;
};

export const startCampaign = async (id: string) => {
    const response = await govApi.post(`/api/v1/campaigns/${id}/start`);
    return response.data;
};

export const completeCampaign = async (id: string) => {
    const response = await govApi.post(`/api/v1/campaigns/${id}/complete`);
    return response.data;
};

export const getCampaignItems = async (campaignId: string) => {
    const response = await govApi.get(`/api/v1/campaigns/${campaignId}/items`);
    return response.data;
};

export const addCampaignItem = async (campaignId: string, item: {
    user_id: string;
    resource_type: string;
    resource_id: string;
    resource_name?: string;
}) => {
    const response = await govApi.post(`/api/v1/campaigns/${campaignId}/items`, item);
    return response.data;
};

export const getReviewItems = async (reviewerId: string) => {
    const response = await govApi.get('/api/v1/campaigns/items', { params: { reviewer_id: reviewerId } });
    return response.data;
};

export const approveItem = async (campaignId: string, itemId: string, comment: string) => {
    const response = await govApi.post(`/api/v1/campaigns/${campaignId}/items/${itemId}/approve`, { comment });
    return response.data;
};

export const revokeItem = async (campaignId: string, itemId: string, comment: string) => {
    const response = await govApi.post(`/api/v1/campaigns/${campaignId}/items/${itemId}/revoke`, { comment });
    return response.data;
};

// SSO Providers
export const getSSOProviders = async () => {
    const response = await govApi.get('/api/v1/sso/providers');
    return response.data;
};

export const getPublicSSOProviders = async (tenantID: string) => {
    const response = await api.get(`/sso/public/${tenantID}`);
    return response.data;
};

export const createSSOProvider = async (provider: Record<string, any>) => {
    const response = await govApi.post('/api/v1/sso/providers', provider);
    return response.data;
};

export const updateSSOProvider = async (id: string, provider: Record<string, any>) => {
    const response = await govApi.put(`/api/v1/sso/providers/${id}`, provider);
    return response.data;
};

export const deleteSSOProvider = async (id: string) => {
    await govApi.delete(`/api/v1/sso/providers/${id}`);
};

export const toggleSSOProvider = async (id: string, enabled: boolean) => {
    const response = await govApi.post(`/api/v1/sso/providers/${id}/toggle`, { enabled });
    return response.data;
};

// Graph Traversal
export const getGraphTraversal = async (subjectID: string) => {
    const response = await govApi.get(`/api/v1/governance/graph/traverse?subject_id=${subjectID}`);
    return response.data;
};

// SAML Service Providers (WardSeal as IdP)
export interface SAMLServiceProvider {
    entity_id: string;
    metadata_url?: string;
    acs_url?: string;
    certificate?: string;
    encrypt_assertions: boolean;
    sign_assertions: boolean;
    created_at?: string;
    updated_at?: string;
}

export const getSAMLProviders = async () => {
    const response = await govApi.get('/api/v1/saml/providers');
    return response.data;
};

export const createSAMLProvider = async (provider: SAMLServiceProvider) => {
    const response = await govApi.post('/api/v1/saml/providers', provider);
    return response.data;
};

export const deleteSAMLProvider = async (entityID: string) => {
    await govApi.delete(`/api/v1/saml/providers/${encodeURIComponent(entityID)}`);
};

// Connectors
export const getConnectors = async () => {
    const response = await govApi.get('/api/v1/connectors');
    return response.data;
};

export const createConnector = async (config: Record<string, any>) => {
    const response = await govApi.post('/api/v1/connectors', config);
    return response.data;
};

export const updateConnector = async (id: string, config: Record<string, any>) => {
    const response = await govApi.put(`/api/v1/connectors/${id}`, config);
    return response.data;
};

export const deleteConnector = async (id: string) => {
    await govApi.delete(`/api/v1/connectors/${id}`);
};

export const toggleConnector = async (id: string, enabled: boolean) => {
    const response = await govApi.post(`/api/v1/connectors/${id}/toggle`, { enabled });
    return response.data;
};

export const testConnector = async (config: Record<string, any>) => {
    const response = await govApi.post('/api/v1/connectors/test', config);
    return response.data;
};

// Branding - Auth Service
export interface BrandingConfig {
    tenant_id: string;
    logo_url: string;
    primary_color: string;
    background_color: string;
    css_override: string;
    config: Record<string, any>;
}

export const getBranding = async (tenantID?: string) => {
    const url = tenantID ? `/branding/public/${tenantID}` : '/api/v1/branding';
    const response = await api.get(url);
    return response.data;
};

export const updateBranding = async (config: BrandingConfig) => {
    const response = await api.put('/api/v1/branding', config);
    return response.data;
};

// Social Login - Auth Service
export const socialLogin = async (provider: string, code?: string, redirect_uri?: string, email?: string, external_id?: string) => {
    const response = await api.post('/social/login', {
        provider,
        code,
        redirect_uri,
        email,
        external_id
    });
    return response.data;
};

// Webhooks
export const getWebhooks = async () => {
    const response = await govApi.get('/api/v1/governance/webhooks');
    return response.data;
};

export const createWebhook = async (url: string, events: string[]) => {
    const response = await govApi.post('/api/v1/governance/webhooks', { url, events });
    return response.data;
};

export const deleteWebhook = async (id: string) => {
    await govApi.delete(`/api/v1/governance/webhooks/${id}`);
};

// Device Management - Auth Service
export const getDevices = async () => {
    const response = await api.get('/api/v1/devices');
    return response.data;
};

export const deleteDevice = async (id: string) => {
    await api.delete(`/api/v1/devices/${id}`);
};

// Organizations - Governance Service
export const getOrganizations = async () => {
    const response = await govApi.get('/api/v1/organizations');
    return response.data;
};

export const createOrganization = async (org: { name: string; display_name?: string; domain?: string }) => {
    const response = await govApi.post('/api/v1/organizations', org);
    return response.data;
};

export const deleteOrganization = async (id: string) => {
    await govApi.delete(`/api/v1/organizations/${id}`);
    return;
};

export const getOrganizationDomains = async (orgId: string) => {
    const response = await govApi.get(`/api/v1/organizations/${orgId}/domain-verification`);
    return response.data;
};

export const generateDomainToken = async (orgId: string) => {
    const response = await govApi.post(`/api/v1/organizations/${orgId}/domain-verification/generate`);
    return response.data;
};

export const verifyDomain = async (orgId: string) => {
    const response = await govApi.post(`/api/v1/organizations/${orgId}/domain-verification/verify`);
    return response.data;
};

// Discovery
export interface DiscoveredResource {
    id: string;
    tenant_id: string;
    source: string;
    resource_type: string;
    external_id: string;
    name: string;
    metadata: any;
    status: 'discovered' | 'promoted' | 'ignored';
    discovered_at: string;
}

export interface DiscoveryJobStatus {
    id: string;
    tenant_id: string;
    status: 'queued' | 'processing' | 'completed' | 'failed';
    progress: number;
    message?: string;
    started_at: string;
    finished_at?: string;
}

export const getDiscoveredResources = async (filter?: string) => {
    const params = filter ? { filter } : {};
    const response = await govApi.get('/api/v1/governance/discovery/resources', { params });
    return response.data.resources;
};

export const triggerDiscoveryScan = async () => {
    const response = await govApi.post('/api/v1/governance/discovery/scan');
    return response.data;
};

export const getDiscoveryJobStatus = async (jobId: string) => {
    const response = await govApi.get(`/api/v1/governance/discovery/jobs/${jobId}`);
    return response.data as DiscoveryJobStatus;
};

// Security Policies (MTPM)
export interface Policy {
    id: string;
    tenant_id: string;
    name: string;
    rule_type: string;
    rule_data: any;
    is_enabled: boolean;
    created_at: string;
    updated_at: string;
}

export const getPolicies = async () => {
    const response = await govApi.get('/api/v1/policies');
    return response.data.policies;
};

export const createPolicy = async (policy: Partial<Policy>) => {
    const response = await govApi.post('/api/v1/policies', policy);
    return response.data;
};

// Developer Portal
export const getDeveloperAnalytics = async () => {
    const response = await api.get('/api/v1/developer/analytics');
    return response.data;
};

export const getAppLogs = async (appId: string) => {
    const response = await api.get(`/api/v1/apps/${appId}/logs`);
    return response.data;
};

export const getAPIKeyLogs = async (keyId: string) => {
    const response = await api.get(`/api/v1/api-keys/${keyId}/logs`);
    return response.data;
};

export const getUserApps = async () => {
    const response = await api.get('/api/v1/user/apps');
    return response.data;
};

export const getUserProfile = async () => {
    const response = await api.get('/api/v1/user/profile');
    return response.data;
};

// Slack Integration
export interface SlackIntegration {
    enabled: boolean;
    team_id?: string;
    app_id?: string;
    webhook_url?: string;
    status: 'not_configured' | 'ready' | 'error';
    error_message?: string;
}

export const getSlackStatus = async () => {
    const response = await govApi.get('/api/v1/integrations/slack');
    return response.data as SlackIntegration;
};

export const configureSlack = async (config: {
    team_id: string;
    app_id: string;
    bot_token?: string;
    signing_secret?: string;
    webhook_url?: string;
    enabled: boolean;
}) => {
    const response = await govApi.put('/api/v1/integrations/slack', config);
    return response.data;
};

export const disconnectSlack = async () => {
    const response = await govApi.delete('/api/v1/integrations/slack');
    return response.data;
};

// Governance Dashboards & Workloads
export interface DashboardStats {
    active_users: number;
    total_groups: number;
    pending_requests: number;
    active_workloads: number;
    risk_profile: Record<string, number>;
    hygiene_score: number;
    connected_orgs: number;
    active_ip_policies: number;
}

export const getGovernanceStats = async () => {
    const response = await govApi.get('/api/v1/governance/stats');
    return response.data as DashboardStats;
};

export const getWorkloads = async () => {
    const response = await govApi.get('/api/v1/governance/workloads');
    return response.data.workloads;
};

export const createWorkload = async (workload: {
    name: string;
    service_handle: string;
    metadata?: Record<string, any>;
}) => {
    const response = await govApi.post('/api/v1/governance/workloads', workload);
    return response.data;
};

export const getRelationships = async (query?: {
    namespace?: string;
    object_id?: string;
    relation?: string;
    subject_type?: string;
    subject_id?: string;
}) => {
    const response = await govApi.get('/api/v1/governance/relationships', { params: query });
    return response.data.relationships;
};

// Security Copilot
export const askAI = async (question: string) => {
    const response = await govApi.post('/api/v1/governance/ask', { question });
    return response.data;
};

export default api;
