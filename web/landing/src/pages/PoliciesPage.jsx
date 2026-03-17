import { Link } from 'react-router-dom';
import { 
  Shield, 
  Lock, 
  Scale, 
  Globe, 
  ExternalLink,
  ChevronRight,
  FileText,
  FileCheck
} from 'lucide-react';

const policyGroups = [
  {
    id: 'privacy',
    title: 'Privacy & Terms',
    icon: <Scale className="w-8 h-8 text-blue-400" />,
    desc: 'Core legal terms and privacy commitments for our platform users.',
    links: [
      { label: 'Privacy Policy', to: '/privacy' },
      { label: 'Terms of Service', to: '/terms' },
      { label: 'Cookie Policy', to: '/cookies' },
      { label: 'Acceptable Use Policy', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/acceptable-use-policy.md', external: true },
    ],
  },
  {
    id: 'security',
    title: 'Security',
    icon: <Shield className="w-8 h-8 text-green-400" />,
    desc: 'Our security posture, incident handling, and trust commitments.',
    links: [
      { label: 'Security & Trust', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/security-and-trust.md', external: true },
      { label: 'Incident & Breach Notification', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/incident-response-and-breach-notification-policy.md', external: true },
      { label: 'Vulnerability Disclosure', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/vulnerability-disclosure-policy.md', external: true },
    ],
  },
  {
    id: 'enterprise',
    title: 'Enterprise & DPA',
    icon: <Lock className="w-8 h-8 text-purple-400" />,
    desc: 'Contractual and operational data processing policies for business.',
    links: [
      { label: 'Data Processing Addendum (DPA)', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/data-processing-addendum-dpa.md', external: true },
      { label: 'Subprocessors & Transfers', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/subprocessors-and-international-transfers.md', external: true },
      { label: 'Retention & Deletion', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/data-retention-and-deletion-policy.md', external: true },
      { label: 'Service Level Policy (SLA)', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/service-level-policy-sla.md', external: true },
    ],
  },
  {
    id: 'regional',
    title: 'Regional Addenda',
    icon: <Globe className="w-8 h-8 text-orange-400" />,
    desc: 'Compliance overlays for India, US, and EU/EEA jurisdictions.',
    links: [
      { label: 'India DPDP Addendum', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/addenda/india-dpdp-addendum.md', external: true },
      { label: 'US State Privacy Addendum', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/addenda/us-state-privacy-addendum.md', external: true },
      { label: 'EU/EEA Addendum', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/addenda/eu-eea-privacy-and-dpa-addendum.md', external: true },
      { label: 'Jurisdiction Matrix', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/jurisdiction-compliance-matrix-india-us-eu.md', external: true },
    ],
  },
];

export default function PoliciesPage() {
  return (
    <main className="policy-index-page">
      <section className="section" style={{ paddingTop: '140px' }}>
        <div className="container">
          <div className="section-header align-center" style={{ marginBottom: '80px' }}>
            <span className="tag">Compliance Center</span>
            <h1>Trust & <span className="gradient-text">Legal Center</span></h1>
            <p style={{ maxWidth: '600px', margin: '24px auto 0' }}>
              We are committed to transparency, security, and the protection of your data. 
              Find all our legal agreements, privacy commitments, and security policies below.
            </p>
          </div>

          <div className="features-grid">
            {policyGroups.map((group) => (
              <article key={group.id} className="feature-card glass animate-on-scroll">
                <div className="feature-icon">{group.icon}</div>
                <h3 className="mb-4">{group.title}</h3>
                <p className="mb-8" style={{ fontSize: '0.95rem' }}>{group.desc}</p>
                
                <div className="policy-links-list" style={{ display: 'grid', gap: '12px' }}>
                  {group.links.map((link) => (
                    link.external ? (
                      <a 
                        key={link.to} 
                        href={link.to} 
                        target="_blank" 
                        rel="noreferrer"
                        className="policy-link-item"
                        style={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          justifyContent: 'space-between',
                          padding: '12px 16px',
                          background: 'rgba(255,255,255,0.03)',
                          borderRadius: 'var(--r)',
                          fontSize: '0.9rem',
                          color: 'var(--text-muted)',
                          textDecoration: 'none',
                          transition: 'var(--transition)',
                          border: '1px solid var(--border)'
                        }}
                      >
                        <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <FileText size={16} className="text-muted" />
                          {link.label}
                        </span>
                        <ExternalLink size={14} style={{ opacity: 0.5 }} />
                      </a>
                    ) : (
                      <Link 
                        key={link.to} 
                        to={link.to}
                        className="policy-link-item"
                        style={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          justifyContent: 'space-between',
                          padding: '12px 16px',
                          background: 'rgba(255,255,255,0.03)',
                          borderRadius: 'var(--r)',
                          fontSize: '0.9rem',
                          color: 'var(--text-muted)',
                          textDecoration: 'none',
                          transition: 'var(--transition)',
                          border: '1px solid var(--border)'
                        }}
                      >
                        <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <FileCheck size={16} className="text-primary" />
                          {link.label}
                        </span>
                        <ChevronRight size={16} style={{ opacity: 0.5 }} />
                      </Link>
                    )
                  ))}
                </div>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="section section-muted">
        <div className="container">
          <div className="cta-glass glass" style={{ padding: '80px 48px', borderRadius: 'var(--r-lg)', textAlign: 'center' }}>
            <h2>Security is at our core</h2>
            <p style={{ maxWidth: '600px', margin: '20px auto 32px' }}>
              WardSeal is designed from the ground up to meet the most stringent security and compliance requirements. 
              Our infrastructure is continuously audited and monitored.
            </p>
            <div className="hero-cta">
              <a href="mailto:security@wardseal.com" className="btn btn-primary">Download Security Whitepaper</a>
              <a href="https://github.com/dhawalhost/wardseal" className="btn btn-outline">Trust Portal</a>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
