import React, { Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from '@/components/theme-provider';
import AdminShell from './components/AdminShell';
import Dashboard from './pages/Dashboard';
import Users from './pages/Users';
import UserForm from './pages/UserForm';
import AccessRequests from './pages/AccessRequests';
import Roles from './pages/Roles';
import AuditLogs from './pages/AuditLogs';
import Campaigns from './pages/Campaigns';
import SafetyInbox from './pages/SafetyInbox';
import SSOConfig from './pages/SSOConfig';
import Connectors from './pages/Connectors';
import Branding from './pages/Branding';
import Webhooks from './pages/Webhooks';
import Devices from './pages/Devices';
import Organizations from './pages/Organizations';
import DeveloperApps from './pages/DeveloperApps';
import DeveloperAnalytics from './pages/DeveloperAnalytics';
import Discovery from './pages/Discovery';
import Policies from './pages/Policies';
import IPPolicies from './pages/IPPolicies';
import Groups from './pages/Groups';
import SlackIntegration from './pages/SlackIntegration';
import GraphExplorer from './pages/GraphExplorer';
import WorkloadManagement from './pages/WorkloadManagement';
import Copilot from './pages/Copilot';
import AuthGuard from './components/AuthGuard';

// Lazy load API docs page (heavy Redoc bundle)
const Developer = React.lazy(() => import('./pages/Developer'));

const LoadingFallback = () => (
  <div className="flex items-center justify-center min-h-screen">
    <div className="text-center space-y-4">
      <div className="w-12 h-12 border-4 border-primary/30 border-t-primary rounded-full animate-spin mx-auto" />
      <p className="text-muted-foreground">Loading...</p>
    </div>
  </div>
);

/**
 * web/admin — Admin Dashboard
 *
 * All routes are protected. Unauthenticated users are redirected to
 * id.wardseal.* login?redirect_uri=<current-url> via AuthGuard.
 *
 * Login/signup pages are NOT served here — that is the responsibility
 * of web/id (id.wardseal.*).
 */
const LoginRedirect: React.FC = () => {
  const idUrl = import.meta.env.VITE_ID_URL ?? 'http://id.wardseal.local';
  React.useEffect(() => {
    const redirectUri = encodeURIComponent(`${window.location.origin}/dashboard`);
    window.location.href = `${idUrl}/login?redirect_uri=${redirectUri}`;
  }, [idUrl]);
  return null;
};

const App: React.FC = () => {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="wardseal-admin-theme">
      <Router>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/login" element={<LoginRedirect />} />

          {/* All admin routes are protected — AuthGuard redirects to id.* if no session */}
          <Route element={<AuthGuard><AdminShell /></AuthGuard>}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/users" element={<Users />} />
            <Route path="/users/new" element={<UserForm />} />
            <Route path="/users/edit/:id" element={<UserForm />} />
            <Route path="/requests" element={<AccessRequests />} />
            <Route path="/roles" element={<Roles />} />
            <Route path="/audit" element={<AuditLogs />} />
            <Route path="/safety" element={<SafetyInbox />} />
            <Route path="/campaigns" element={<Campaigns />} />
            <Route path="/sso" element={<SSOConfig />} />
            <Route path="/connectors" element={<Connectors />} />
            <Route path="/developer" element={<Suspense fallback={<LoadingFallback />}><Developer /></Suspense>} />
            <Route path="/developer/analytics" element={<DeveloperAnalytics />} />
            <Route path="/apps" element={<DeveloperApps />} />
            <Route path="/branding" element={<Branding />} />
            <Route path="/webhooks" element={<Webhooks />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/organizations" element={<Organizations />} />
            <Route path="/discovery" element={<Discovery />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/policies/ip" element={<IPPolicies />} />
            <Route path="/groups" element={<Groups />} />
            <Route path="/graph-explorer" element={<GraphExplorer />} />
            <Route path="/workloads" element={<WorkloadManagement />} />
            <Route path="/integrations/slack" element={<SlackIntegration />} />
            <Route path="/copilot" element={<Copilot />} />
          </Route>

          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Router>
    </ThemeProvider>
  );
};

export default App;
