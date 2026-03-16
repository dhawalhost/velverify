import React from 'react';
import PolicyLayout from '../components/PolicyLayout';

export default function CookiePolicy() {
  return (
    <PolicyLayout title="Cookie Policy" lastUpdated="15 March 2026">
      <div className="prose">
        <p>This Cookie Policy explains how WardSeal uses cookies and similar technologies.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>1. What are cookies?</h2>
        <p>Cookies are small text files placed on a device when a user visits a website or web application.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>2. Why we use cookies</h2>
        <p>We use cookies and similar technologies for:</p>
        <ul>
          <li>Essential service functionality</li>
          <li>Security and fraud prevention</li>
          <li>Session continuity and authentication support</li>
          <li>Analytics and product improvement (if enabled)</li>
        </ul>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>3. Cookie categories</h2>
        <h3 style={{ color: '#fff', marginTop: '24px' }}>3.1 Strictly Necessary</h3>
        <p>Required for core platform operation, including authentication/session handling and security protections.</p>

        <h3 style={{ color: '#fff', marginTop: '24px' }}>3.2 Functional</h3>
        <p>Used to remember user preferences and improve usability.</p>

        <h3 style={{ color: '#fff', marginTop: '24px' }}>3.3 Analytics (optional)</h3>
        <p>Used to understand service usage and improve product performance. We request consent where required.</p>

        <h3 style={{ color: '#fff', marginTop: '24px' }}>3.4 Marketing (if used)</h3>
        <p>Used for campaign attribution or advertising. These are disabled by default unless explicitly configured.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>4. Cookie controls</h2>
        <p>Users can control cookies through browser settings. Blocking strictly necessary cookies may impact service functionality. Where required, we provide consent controls for non-essential cookies.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>5. Enterprise self-hosted deployments</h2>
        <p>For self-hosted deployments, the customer controls site configuration and any analytics/marketing scripts deployed in their environment.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>6. Updates</h2>
        <p>We may update this Cookie Policy over time. Material updates will be announced as appropriate.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>7. Contact</h2>
        <p>For questions: <strong>privacy@wardseal.com</strong></p>
      </div>
    </PolicyLayout>
  );
}
