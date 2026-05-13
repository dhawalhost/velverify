import React, { Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from '@/components/theme-provider';
import AdminShell from './components/AdminShell';
import DeveloperApps from './pages/DeveloperApps';
import DeveloperAnalytics from './pages/DeveloperAnalytics';
import Webhooks from './pages/Webhooks';
import AuthGuard from './components/AuthGuard';

// Lazy load the Redoc API docs (very large bundle)
const Developer = React.lazy(() => import('./pages/Developer'));

const LoadingFallback = () => (
  <div className="flex items-center justify-center min-h-screen">
    <div className="text-center space-y-4">
      <div className="w-12 h-12 border-4 border-primary/30 border-t-primary rounded-full animate-spin mx-auto" />
      <p className="text-muted-foreground">Loading API documentation...</p>
    </div>
  </div>
);

/**
 * web/developer — Developer Portal
 *
 * OAuth app management, API documentation, analytics, and webhooks.
 * Login is handled by id.wardseal.* — AuthGuard redirects there if no session.
 */
const App: React.FC = () => {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="wardseal-developer-theme">
      <Router>
        <Routes>
          <Route path="/" element={<Navigate to="/developer" replace />} />

          <Route element={<AuthGuard><AdminShell /></AuthGuard>}>
            <Route path="/developer" element={<Suspense fallback={<LoadingFallback />}><Developer /></Suspense>} />
            <Route path="/developer/analytics" element={<DeveloperAnalytics />} />
            <Route path="/apps" element={<DeveloperApps />} />
            <Route path="/webhooks" element={<Webhooks />} />
          </Route>

          <Route path="*" element={<Navigate to="/developer" replace />} />
        </Routes>
      </Router>
    </ThemeProvider>
  );
};

export default App;
