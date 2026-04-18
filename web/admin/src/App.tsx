import React, { Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from "@/components/theme-provider";
import Layout from './components/Layout';
import Login from './pages/Login';
import SignUp from './pages/SignUp';
import Setup from './pages/Setup';
import SetPassword from './pages/SetPassword';
import Dashboard from './pages/Dashboard';
import Users from './pages/Users';
import UserForm from './pages/UserForm';

import AccessRequests from './pages/AccessRequests';
import RequestAccess from './pages/RequestAccess';
import Roles from './pages/Roles';
import AuditLogs from './pages/AuditLogs';
import Campaigns from './pages/Campaigns';
import SafetyInbox from './pages/SafetyInbox';

import SSOConfig from './pages/SSOConfig';
import Connectors from './pages/Connectors';
import Passkeys from './pages/Passkeys';
import Branding from './pages/Branding';
import Webhooks from './pages/Webhooks';
import Devices from './pages/Devices';
import MFASetup from './pages/MFASetup';
import Organizations from './pages/Organizations';
import DeveloperApps from './pages/DeveloperApps';
import DeveloperAnalytics from './pages/DeveloperAnalytics';
import Discovery from '@/pages/Discovery';
import Policies from '@/pages/Policies';

import PortalLayout from './layouts/PortalLayout';
import PortalDashboard from './pages/PortalDashboard';
import PortalProfile from './pages/PortalProfile';

// Lazy load Developer page to reduce initial bundle size
const Developer = React.lazy(() => import('./pages/Developer'));

// Basic protected route
const ProtectedRoute = ({ children }: { children: JSX.Element }) => {
  const token = localStorage.getItem('token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return children;
};

// Loading fallback component
const LoadingFallback = () => (
  <div className="flex items-center justify-center min-h-screen">
    <div className="text-center space-y-4">
      <div className="w-12 h-12 border-4 border-primary/30 border-t-primary rounded-full animate-spin mx-auto"></div>
      <p className="text-muted-foreground">Loading API documentation...</p>
    </div>
  </div>
);

const App: React.FC = () => {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="wardseal-ui-theme">
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/setup" element={<Setup />} />
          <Route path="/set-password" element={<SetPassword />} />
          <Route path="/signup" element={<SignUp />} />

          {/* Root redirects to login */}
          <Route path="/" element={<Navigate to="/login" replace />} />

          {/* User Portal Routes */}
          <Route path="/portal" element={<ProtectedRoute><PortalLayout /></ProtectedRoute>}>
            <Route index element={<PortalDashboard />} />
            <Route path="profile" element={<PortalProfile />} />
            {/* Add Profile/Security routes later */}
          </Route>

          {/* Protected Admin Routes */}
          <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/users" element={<Users />} />
            <Route path="/users/new" element={<UserForm />} />
            <Route path="/requests" element={<AccessRequests />} />
            <Route path="/request-access" element={<RequestAccess />} />
            <Route path="/roles" element={<Roles />} />
            <Route path="/audit" element={<AuditLogs />} />
            <Route path="/safety" element={<SafetyInbox />} />
            <Route path="/campaigns" element={<Campaigns />} />
            <Route path="/sso" element={<SSOConfig />} />
            <Route path="/connectors" element={<Connectors />} />
            <Route path="/developer" element={<Suspense fallback={<LoadingFallback />}><Developer /></Suspense>} />
            <Route path="/developer/analytics" element={<DeveloperAnalytics />} />
            <Route path="/passkeys" element={<Passkeys />} />
            <Route path="/branding" element={<Branding />} />
            <Route path="/webhooks" element={<Webhooks />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/mfa" element={<MFASetup />} />
            <Route path="/organizations" element={<Organizations />} />
            <Route path="/apps" element={<DeveloperApps />} />
            <Route path="/discovery" element={<Discovery />} />
            <Route path="/policies" element={<Policies />} />
          </Route>
        </Routes>
      </Router >
    </ThemeProvider >
  );
};

export default App;
