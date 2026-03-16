import React from 'react';
import PolicyLayout from '../components/PolicyLayout';

export default function TermsOfService() {
  return (
    <PolicyLayout title="Terms of Service" lastUpdated="15 March 2026">
      <div className="prose">
        <p>These Terms of Service ("Terms") govern access to and use of WardSeal services provided by Wardseal ("WardSeal", "we", "us").</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>1. Agreement and eligibility</h2>
        <p>By using WardSeal, you agree to these Terms on behalf of yourself or your organization. You represent that you have authority to bind the organization.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>2. Services</h2>
        <p>WardSeal provides identity and access management services, including authentication, user and tenant management, policy/governance features, and related APIs.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>3. Accounts and security</h2>
        <p>You are responsible for:</p>
        <ul>
          <li>Maintaining account credentials and administrative access controls</li>
          <li>Configuring integrations and redirect URIs correctly</li>
          <li>Promptly notifying WardSeal of unauthorized access</li>
        </ul>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>4. Acceptable use</h2>
        <p>You must comply with the <strong>Acceptable Use Policy</strong>. You may not use the service for unlawful, abusive, or harmful activities.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>5. Customer data</h2>
        <p>As between the parties, Customer retains all rights to Customer Data. WardSeal processes Customer Data to provide the services and as described in the Privacy Policy and DPA.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>6. Fees and payment</h2>
        <p>Fees, billing cycle, and payment terms are specified in your order form or subscription plan.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>7. Intellectual property</h2>
        <p>WardSeal and related technology are owned by Wardseal and licensors. No ownership rights are transferred except as explicitly stated.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>8. Third-party services</h2>
        <p>You may connect third-party services at your option. WardSeal is not responsible for third-party services.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>9. Suspension and termination</h2>
        <p>WardSeal may suspend or terminate access for material breach, security risk, or unlawful use, subject to applicable notice obligations.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>10. Warranties disclaimer</h2>
        <p>Except as expressly provided, services are provided "as is" and "as available" to the maximum extent permitted by law.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>11. Limitation of liability</h2>
        <p>To the maximum extent permitted by law:</p>
        <ul>
          <li>Neither party is liable for indirect, incidental, special, consequential, or punitive damages.</li>
          <li>Each party’s aggregate liability is limited to amounts paid or payable in the 12-month period before the event giving rise to liability.</li>
        </ul>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>12. Indemnification</h2>
        <p>Each party’s indemnification obligations (if any) are defined in the applicable commercial agreement or order form.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>13. Confidentiality</h2>
        <p>Each party will protect the other party’s Confidential Information using reasonable care and use it only to perform obligations under the agreement.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>14. Governing law and venue</h2>
        <p>These Terms are governed by region-specific law and venue, unless otherwise required by mandatory applicable law:</p>
        <ul>
          <li>India customers: laws of India; venue in courts having jurisdiction over Vapi, Gujarat.</li>
          <li>EU/EEA customers: governing law and venue as specified in the applicable EU/EEA order form or regional addendum.</li>
          <li>U.S. customers: governing law and venue as specified in the applicable U.S. order form or regional addendum.</li>
        </ul>
        <p>For customers in India, the EU/EEA, or specific U.S. states, mandatory local consumer/data protection laws may apply notwithstanding this clause.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>15. Changes</h2>
        <p>WardSeal may modify these Terms. Material changes will be communicated in advance when required by law or contract.</p>

        <h2 style={{ color: '#fff', marginTop: '32px' }}>16. Contact</h2>
        <p>Legal notices: <strong>legal@wardseal.com</strong></p>
      </div>
    </PolicyLayout>
  );
}
