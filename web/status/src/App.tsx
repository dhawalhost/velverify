import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from '@/components/theme-provider';
import StatusPage from './pages/StatusPage';

/**
 * web/status — Public Status Page
 *
 * Read-only, publicly accessible. No authentication required.
 * Shows current health and uptime of WardSeal services.
 */
const App: React.FC = () => {
  return (
    <ThemeProvider defaultTheme="light" storageKey="wardseal-status-theme">
      <Router>
        <Routes>
          <Route path="/" element={<StatusPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
    </ThemeProvider>
  );
};

export default App;
