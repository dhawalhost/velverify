import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from '@/components/theme-provider';
import PortalLayout from './layouts/PortalLayout';
import PortalDashboard from './pages/PortalDashboard';
import PortalProfile from './pages/PortalProfile';
import RequestAccess from './pages/RequestAccess';
import AccessRequests from './pages/AccessRequests';
import Passkeys from './pages/Passkeys';
import Devices from './pages/Devices';
import MFASetup from './pages/MFASetup';
import AuthGuard from './components/AuthGuard';

/**
 * web/app — User App Portal
 *
 * End-user self-service: app launcher, profile, and access requests.
 * Login is handled by id.wardseal.* — AuthGuard redirects there if no session.
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
    <ThemeProvider defaultTheme="dark" storageKey="wardseal-app-theme">
      <Router>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/login" element={<LoginRedirect />} />

          <Route element={<AuthGuard><PortalLayout /></AuthGuard>}>
            <Route path="/dashboard" element={<PortalDashboard />} />
            <Route path="/profile" element={<PortalProfile />} />
            <Route path="/request-access" element={<RequestAccess />} />
            <Route path="/requests" element={<AccessRequests />} />
            <Route path="/passkeys" element={<Passkeys />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/mfa" element={<MFASetup />} />
          </Route>

          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Router>
    </ThemeProvider>
  );
};

export default App;
