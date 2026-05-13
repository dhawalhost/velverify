import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from '@/components/theme-provider';
import Login from './pages/Login';
import SignUp from './pages/SignUp';
import Setup from './pages/Setup';
import SetPassword from './pages/SetPassword';
import MFASetup from './pages/MFASetup';
import Passkeys from './pages/Passkeys';
import PortalProfile from './pages/PortalProfile';
import PortalDashboard from './pages/PortalDashboard';
import Callback from './pages/Callback';
import SocialCallback from './pages/SocialCallback';
import Logout from './pages/Logout';
import PortalLayout from './layouts/PortalLayout';

/**
 * web/id — Identity / Login UI
 *
 * This is the single login entry point for all WardSeal applications.
 * After a successful login, the user is redirected back to the
 * ?redirect_uri query parameter (their original destination).
 *
 * Protected routes (profile, passkeys, mfa) show account self-service.
 * All authentication API calls go to VITE_AUTH_URL (auth.wardseal.*).
 */
const App: React.FC = () => {
  return (
    <ThemeProvider defaultTheme="light" storageKey="wardseal-id-theme">
      <Router>
        <Routes>
          {/* Public auth flows */}
          <Route path="/login" element={<Login />} />
          <Route path="/t/:tenantID/login" element={<Login />} />
          <Route path="/signup" element={<SignUp />} />
          <Route path="/setup" element={<Setup />} />
          <Route path="/set-password" element={<SetPassword />} />
          <Route path="/logout" element={<Logout />} />
          <Route path="/t/:tenantID/logout" element={<Logout />} />

          {/* Post-login redirect handler — reads ?redirect_uri and navigates there */}
          <Route path="/callback" element={<Callback />} />
          <Route path="/social/callback" element={<SocialCallback />} />

          {/* Self-service account management (requires active session) */}
          <Route element={<PortalLayout />}>
            <Route path="/profile" element={<PortalProfile />} />
            <Route path="/mfa" element={<MFASetup />} />
            <Route path="/passkeys" element={<Passkeys />} />
            <Route path="/portal" element={<PortalDashboard />} />
            <Route path="/dashboard" element={<Navigate to="/portal" replace />} />
          </Route>

          {/* Default: go to login */}
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </Router>
    </ThemeProvider>
  );
};

export default App;
