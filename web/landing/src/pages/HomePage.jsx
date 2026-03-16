import { useMemo, useState, useEffect } from 'react'
import { 
  ShieldCheck, 
  Users, 
  Key, 
  Target, 
  Settings, 
  Building2, 
  Zap, 
  Star,
  Lock,
  RotateCw,
  Fingerprint,
  Layers,
  Activity,
  ArrowRight
} from 'lucide-react'
import siteConfig from '../siteConfig'

const { consoleBaseUrl } = siteConfig

const pricing = {
  monthly: { pro: 29, team: 99 },
  yearly: { pro: 23, team: 79 },
}

const faqItems = [
  {
    q: 'Can I self-host WardSeal?',
    a: 'Yes — WardSeal is fully open source (MIT). Deploy it on any Kubernetes cluster, VM, or bare metal using the Helm chart or Docker Compose. The self-host version includes all platform features.',
  },
  {
    q: 'How does MAU pricing work?',
    a: 'A Monthly Active User (MAU) is any unique end-user who authenticates at least once in a month. Internal admin accounts don\'t count.',
  },
  {
    q: 'Do you support enterprise SSO?',
    a: 'Yes. WardSeal supports any standards-compliant OIDC or SAML 2.0 provider, including Okta, Azure AD, Google Workspace, and more.',
  },
]

const features = [
  { icon: <Lock className="w-8 h-8 text-blue-400" />, title: 'Enterprise SSO', desc: 'OIDC & SAML 2.0 federation with any IdP — Okta, Azure AD, Google Workspace, and more.' },
  { icon: <ShieldCheck className="w-8 h-8 text-green-400" />, title: 'Adaptive MFA', desc: 'TOTP, WebAuthn passkeys, magic links, and risk-based step-up auth to stop account takeovers.' },
  { icon: <Users className="w-8 h-8 text-purple-400" />, title: 'Directory & SCIM', desc: 'Full user lifecycle management with SCIM 2.0 provisioning. Auto-sync in real time.' },
  { icon: <Target className="w-8 h-8 text-red-400" />, title: 'Identity Governance', desc: 'Automated access reviews, certification campaigns, and approval workflows.' },
  { icon: <Settings className="w-8 h-8 text-orange-400" />, title: 'Fine-grained RBAC', desc: 'Roles, policies, and resource-level permissions managed through API or visual console.' },
  { icon: <Building2 className="w-8 h-8 text-cyan-400" />, title: 'Multi-tenancy', desc: 'Isolated namespaces, branding, and SSO for thousands of customer orgs from one deployment.' },
]

const testimonials = [
  { quote: "WardSeal's SCIM provisioning cut our onboarding time from hours to minutes.", author: "Priya S.", role: "Head of Platform, FinStack" },
  { quote: "Self-hosting on k8s was trivial. We had SSO working with Azure AD in under 30 minutes.", author: "Marcus R.", role: "CTO, Datawave" },
  { quote: "The multi-tenant support is first-class. Each customer gets an isolated identity namespace.", author: "Chen W.", role: "Engineering Manager, SaaSly" },
]



export default function HomePage() {
  const [yearly, setYearly] = useState(false)
  const [openFaq, setOpenFaq] = useState(0)

  const proPrice = yearly ? pricing.yearly.pro : pricing.monthly.pro
  const teamPrice = yearly ? pricing.yearly.team : pricing.monthly.team

  useEffect(() => {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(e => { 
        if (e.isIntersecting) { 
          e.target.classList.add('fade-up'); 
          observer.unobserve(e.target); 
        } 
      });
    }, { threshold: 0.1 });

    document.querySelectorAll('.animate-on-scroll').forEach(el => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  return (
    <main>
      <section className="hero">
        <div className="container hero-content fade-up">
          <div className="hero-text">
            <span className="tag"><Zap className="w-3 h-3" /> v1.0 — Enterprise Ready</span>
            <h1>
              Identity Infrastructure for the <span className="gradient-text">Modern Cloud</span>
            </h1>
            <p>
              Open-source IAM that ships SSO, Adaptive MFA, and Zero Trust access control in minutes — self-host or cloud.
            </p>
            <div className="hero-cta">
              <a className="btn btn-primary" href={`${consoleBaseUrl}/signup?plan=free`}>
                Start for Free <ArrowRight className="w-4 h-4 ml-2" />
              </a>
              <a className="btn btn-outline" href="https://github.com/dhawalhost/wardseal" target="_blank" rel="noreferrer">
                <Star className="w-4 h-4 mr-2" /> Star on GitHub
              </a>
            </div>
          </div>
          <div className="hero-mockup">
            <img src="/console-preview.png" alt="WardSeal Console Preview" className="mockup-img" />
          </div>
        </div>
      </section>

      <section className="stats-bar">
        <div className="container stats-grid">
          <div className="stat"><div className="stat-value">10k+</div><div className="stat-label"><Users className="w-3 h-3 mr-1 inline" /> Developers</div></div>
          <div className="stat"><div className="stat-value">500+</div><div className="stat-label"><Building2 className="w-3 h-3 mr-1 inline" /> Companies</div></div>
          <div className="stat"><div className="stat-value">99.99%</div><div className="stat-label"><ShieldCheck className="w-3 h-3 mr-1 inline" /> Uptime SLA</div></div>
          <div className="stat"><div className="stat-value">&lt;50ms</div><div className="stat-label"><Activity className="w-3 h-3 mr-1 inline" /> Auth latency</div></div>
        </div>
      </section>

      <section className="section" id="features">
        <div className="container">
          <div className="section-header align-center">
            <span className="tag">Platform</span>
            <h2>Enterprise security, simplified</h2>
            <p>One platform for users, machines, and compliance.</p>
          </div>
          <div className="features-grid">
            {features.map((f, i) => (
              <article className="feature-card animate-on-scroll" key={i}>
                <div className="feature-icon">{f.icon}</div>
                <h3>{f.title}</h3>
                <p>{f.desc}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="section section-muted">
        <div className="container">
          <div className="how-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '60px', alignItems: 'center' }}>
            <div>
              <span className="tag" style={{ marginBottom: '24px' }}>Quick Start</span>
              <h2 style={{ marginBottom: '32px' }}>Up and running in minutes</h2>
              <div className="steps" style={{ display: 'grid', gap: '32px' }}>
                {[
                  { n: 1, t: 'Create your account', d: 'Sign up for free. Your tenant is provisioned instantly.' },
                  { n: 2, t: 'Connect your app', d: 'Register an OIDC/OAuth app. Copy the client ID.' },
                  { n: 3, t: 'Configure SSO & MFA', d: 'Enable social login or passkeys in a few clicks.' }
                ].map(s => (
                  <div className="step" key={s.n} style={{ display: 'flex', gap: '20px' }}>
                    <div className="step-num" style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'var(--primary)', display: 'flex', alignItems: 'center', justifyCenter: 'center', flexShrink: 0, fontWeight: 'bold' }}>{s.n}</div>
                    <div>
                      <h3 style={{ fontSize: '1.1rem', marginBottom: '4px' }}>{s.t}</h3>
                      <p style={{ fontSize: '0.95rem' }}>{s.d}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="code-box animate-on-scroll">
              <span className="comment"># Install via Helm</span><br />
              <span className="cmd">helm</span> repo add wardseal https://charts.wardseal.com<br />
              <span className="cmd">helm</span> install wardseal wardseal/wardseal \<br />
              &nbsp;&nbsp;--set auth.domain=auth.example.com<br /><br />
              <span className="comment"># OIDC discovery</span><br />
              <span className="cmd">curl</span> https://auth.example.com/.well-known/openid-configuration<br /><br />
              <span className="ok">✓ Issuer live</span><br />
              <span className="ok">✓ JWKS ready</span><br />
              <span className="ok">✓ MFA active</span>
            </div>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <div className="section-header align-center">
            <span className="tag">Testimonials</span>
            <h2>Trusted by engineering teams</h2>
          </div>
          <div className="features-grid" style={{ marginTop: '40px' }}>
            {testimonials.map((t, i) => (
              <div className="feature-card animate-on-scroll" key={i} style={{ borderLeft: '4px solid var(--primary)' }}>
                <p style={{ fontStyle: 'italic', marginBottom: '24px', fontSize: '1rem', color: '#fff' }}>"{t.quote}"</p>
                <div>
                  <div style={{ fontWeight: 'bold' }}>{t.author}</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-dim)' }}>{t.role}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="section section-muted" id="pricing">
        <div className="container">
          <div className="section-header align-center">
            <span className="tag">Pricing</span>
            <h2>Simple, transparent pricing</h2>
          </div>

          <div className="pricing-toggle">
            <span style={{ color: !yearly ? 'var(--text)' : 'var(--text-dim)' }}>Monthly</span>
            <button
              type="button"
              className={`toggle-wrap ${yearly ? 'active' : ''}`}
              onClick={() => setYearly((v) => !v)}
            >
              <div className="toggle-knob" />
            </button>
            <span style={{ color: yearly ? 'var(--text)' : 'var(--text-dim)' }}>Yearly</span>
            <span className="tag" style={{ background: 'rgba(34, 197, 94, 0.1)', color: '#22c55e', borderColor: 'rgba(34, 197, 94, 0.2)' }}>Save 20%</span>
          </div>

          <div className="pricing-grid">
            <article className="plan-card animate-on-scroll">
              <h3 className="plan-name">Community</h3>
              <p className="plan-desc">Self-hosted Open Source</p>
              <div className="plan-price"><span className="plan-amount">$0</span><span className="plan-per">/forever</span></div>
              <ul className="plan-features">
                <li className="plan-feature"><span className="check">✓</span> Core Identity Engine</li>
                <li className="plan-feature"><span className="check">✓</span> Unlimited self-hosted MAUs</li>
                <li className="plan-feature"><span className="check">✓</span> Community Support</li>
                <li className="plan-feature disabled"><span className="cross">✗</span> Managed Cloud Hosting</li>
              </ul>
              <a className="btn btn-outline" style={{ width: '100%' }} href="/docs/deployment/self-hosting">Self-Host Now</a>
            </article>

            <article className="plan-card popular animate-on-scroll">
              <span className="plan-badge">SaaS Managed</span>
              <h3 className="plan-name">Pro Cloud</h3>
              <p className="plan-desc">Fully managed by WardSeal</p>
              <div className="plan-price"><span className="plan-amount">${proPrice}</span><span className="plan-per">/mo</span></div>
              <ul className="plan-features">
                <li className="plan-feature"><span className="check">✓</span> Up to 10,000 MAUs</li>
                <li className="plan-feature"><span className="check">✓</span> Automated Backups & HA</li>
                <li className="plan-feature"><span className="check">✓</span> Priority Support</li>
                <li className="plan-feature"><span className="check">✓</span> Custom Domain Support</li>
              </ul>
              <a className="btn btn-primary" style={{ width: '100%' }} href={`${consoleBaseUrl}/signup?plan=pro`}>Start Cloud Trial</a>
            </article>

            <article className="plan-card animate-on-scroll">
              <h3 className="plan-name">Enterprise</h3>
              <p className="plan-desc">For large platforms</p>
              <div className="plan-price"><span className="plan-amount">Custom</span></div>
              <ul className="plan-features">
                <li className="plan-feature"><span className="check">✓</span> Unlimited MAUs</li>
                <li className="plan-feature"><span className="check">✓</span> Dedicated Support</li>
                <li className="plan-feature"><span className="check">✓</span> Custom SLAs & Compliance</li>
                <li className="plan-feature"><span className="check">✓</span> Shared-Success Program</li>
              </ul>
              <a className="btn btn-outline" style={{ width: '100%' }} href="mailto:sales@wardseal.com">Contact Sales</a>
            </article>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container faq">
          <div className="section-header align-center">
            <span className="tag">FAQ</span>
            <h2>Frequently asked questions</h2>
          </div>
          <div style={{ marginTop: '40px' }}>
            {faqItems.map((item, idx) => (
              <div className={`faq-item ${openFaq === idx ? 'open' : ''}`} key={item.q}>
                <button className="faq-q" onClick={() => setOpenFaq(openFaq === idx ? -1 : idx)}>
                  {item.q}
                  <span className="faq-icon">+</span>
                </button>
                <div className="faq-a">{item.a}</div>
              </div>
            ))}
          </div>
        </div>
      </section>


      <section className="section">
        <div className="container" style={{ textAlign: 'center' }}>
          <div className="glass" style={{ padding: '80px', borderRadius: 'var(--r-lg)', background: 'radial-gradient(circle at top right, var(--primary-surface), transparent)' }}>
            <span className="tag" style={{ marginBottom: '24px' }}>Get Started</span>
            <h2 style={{ marginBottom: '24px' }}>Secure your application today</h2>
            <p style={{ maxWidth: '600px', margin: '0 auto 40px' }}>Free forever for small projects. No credit card. No lock-in.</p>
            <div className="hero-cta">
              <a className="btn btn-primary" href={`${consoleBaseUrl}/signup`}>Create Free Account &rarr;</a>
              <a className="btn btn-outline" href="https://github.com/dhawalhost/wardseal">Read the Docs</a>
            </div>
          </div>
        </div>
      </section>
    </main>
  )
}
