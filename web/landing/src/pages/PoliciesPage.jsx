import { Link } from 'react-router-dom';

const policyGroups = [
  {
    id: 'privacy',
    title: 'Privacy & Terms',
    desc: 'Core legal terms and privacy commitments.',
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
    desc: 'Security posture and incident handling.',
    links: [
      { label: 'Security & Trust', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/security-and-trust.md', external: true },
      { label: 'Incident & Breach Notification', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/incident-response-and-breach-notification-policy.md', external: true },
      { label: 'Vulnerability Disclosure', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/vulnerability-disclosure-policy.md', external: true },
    ],
  },
  {
    id: 'enterprise',
    title: 'Enterprise & DPA',
    desc: 'Contractual and operational data processing policies.',
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
    desc: 'India, US, and EU/EEA overlays.',
    links: [
      { label: 'India DPDP Addendum', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/addenda/india-dpdp-addendum.md', external: true },
      { label: 'US State Privacy Addendum', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/addenda/us-state-privacy-addendum.md', external: true },
      { label: 'EU/EEA Addendum', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/addenda/eu-eea-privacy-and-dpa-addendum.md', external: true },
      { label: 'Jurisdiction Matrix', to: 'https://github.com/dhawalhost/wardseal/blob/main/docs/policies/jurisdiction-compliance-matrix-india-us-eu.md', external: true },
    ],
  },
]

export default function PoliciesPage() {
  return (
    <main>
      <section className="section">
        <div className="container policies-wrap">
          <div className="section-header policies-header">
            <span className="tag">Compliance</span>
            <h1>Legal, Privacy &amp; Security Policies</h1>
            <p>Policy index for India, US, and EU/EEA audiences.</p>
          </div>

          <div className="policies-grid">
            {policyGroups.map((group) => (
              <article key={group.id} id={group.id} className="policy-card">
                <h3>{group.title}</h3>
                <p>{group.desc}</p>
                <div className="policy-links">
                  {group.links.map((link) => (
                    link.external ? (
                      <a key={link.to} href={link.to} target="_blank" rel="noreferrer">{link.label}</a>
                    ) : (
                      <Link key={link.to} to={link.to}>{link.label}</Link>
                    )
                  ))}
                </div>
              </article>
            ))}
          </div>
        </div>
      </section>
    </main>
  )
}
