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
    q: 'How can I participate in the Public Beta?',
    a: 'Simply create an account via our Cloud Managed portal. During the beta period, you can test all platform features including SSO, MFA, and Identity Governance at no cost.',
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
  { icon: <Lock className="w-8 h-8 text-blue-400" />, title: 'Enterprise SSO', desc: 'Secure OIDC & SAML 2.0 federation with any IdP — Okta, Azure AD, Google Workspace, and more.' },
  { icon: <ShieldCheck className="w-8 h-8 text-green-400" />, title: 'Adaptive MFA', desc: 'TOTP, WebAuthn passkeys, and risk-based step-up auth.' },
  { icon: <Building2 className="w-8 h-8 text-cyan-400" />, title: 'B2B Multi-tenancy', desc: 'Isolated namespaces, branding, and SSO for each of your customer organizations from one deployment.' },
  { icon: <Users className="w-8 h-8 text-purple-400" />, title: 'Directory & SCIM', desc: 'Full user lifecycle management with SCIM 2.0 provisioning.' },
  { icon: <Target className="w-8 h-8 text-red-400" />, title: 'Identity Governance', desc: 'Automated access reviews and certification campaigns.' },
  { icon: <Settings className="w-8 h-8 text-orange-400" />, title: 'Fine-grained RBAC', desc: 'Roles, policies, and resource-level permissions managed through API.' },
]





export default function HomePage() {
  const [activeStep, setActiveStep] = useState(1);
  const [openFaq, setOpenFaq] = useState(0)

  const codeSnippets = {
    1: {
      comment: "// Initialize Cloud Tenant",
      commands: [
        { cmd: "wardseal", text: "login --domain cloud.wardseal.com" },
        { cmd: "wardseal", text: 'tenant create --name "HighGrowth Inc"' }
      ]
    },
    2: {
      comment: "// Register OIDC Application",
      commands: [
        { cmd: "wardseal", text: 'apps create --name "Production App" \\' },
        { cmd: "", text: '  --type "oidc" --redirect-uri "https://app.com/callback"' }
      ]
    },
    3: {
      comment: "// Configuration & Discovery",
      commands: [
        { cmd: "curl", text: "https://cloud.wardseal.com/auth/.well-known/openid-configuration" },
        { cmd: "wardseal", text: "policies create --file prod-security.yaml" }
      ]
    }
  };

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
        <div className="container hero-content">
          <div className="hero-text fade-up">
            <span className="tag"><Zap size={14} /> Unified Identity for the Modern Stack</span>
            <h1>
              Trusted infrastructure <br/>
              for <span className="gradient-text">security teams</span>
            </h1>
            <p>
              The enterprise standard for AuthN, AuthZ, and Identity Governance. 
              Built for performance, auditability, and scale.
            </p>
            <div className="hero-cta">
              <a className="btn btn-primary btn-lg btn-glow" href={`${consoleBaseUrl}/signup`}>
                Start Building Free <ArrowRight size={18} />
              </a>
              <a className="btn btn-outline btn-lg" href="https://github.com/dhawalhost/wardseal">
                Documentation
              </a>
            </div>
            
            <div className="hero-badges">
              <div className="badge-item">
                <Lock size={14} />
                <span>OIDC & SAML 2.0</span>
              </div>
              <div className="badge-divider" />
              <div className="badge-item">
                <ShieldCheck size={14} />
                <span>Adaptive MFA</span>
              </div>
              <div className="badge-divider" />
              <div className="badge-item">
                <Fingerprint size={14} />
                <span>Passkeys</span>
              </div>
            </div>
          </div>

          <div className="hero-mockup fade-up" style={{ animationDelay: '0.2s' }}>
            <div className="mockup-container">
               <img src="/console-preview.png" alt="WardSeal Console Preview" className="mockup-img" />
            </div>
          </div>
        </div>
      </section>

      <section className="section" id="features">
        <div className="container">
          <div className="section-header align-center animate-on-scroll">
            <span className="tag">Platform</span>
            <h2>Enterprise security, simplified</h2>
            <p>One platform for users, machines, and compliance.</p>
          </div>
          <div className="features-grid">
            {features.map((f, i) => (
              <article className="feature-card animate-on-scroll" key={i} style={{ animationDelay: `${i * 0.1}s` }}>
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
          <div className="how-grid">
            <div className="how-text">
              <span className="tag" style={{ marginBottom: '16px' }}>Quick Start</span>
              <h2>Up and running in minutes</h2>
              <div className="steps">
                {[
                  { n: 1, t: 'Create your account', d: 'Sign up for free. Your tenant is provisioned instantly.' },
                  { n: 2, t: 'Connect your app', d: 'Register an OIDC/OAuth app. Copy the client ID.' },
                  { n: 3, t: 'Configure SSO & MFA', d: 'Enable social login or passkeys in a few clicks.' }
                ].map(s => (
                  <div 
                    className={`step ${activeStep === s.n ? 'active' : ''}`} 
                    key={s.n}
                    onMouseEnter={() => setActiveStep(s.n)}
                    style={{ cursor: 'pointer' }}
                  >
                    <div className="step-num">{s.n}</div>
                    <div className="step-content">
                      <h3 style={{ color: activeStep === s.n ? 'var(--primary)' : 'inherit' }}>{s.t}</h3>
                      {activeStep === s.n && <p style={{ fontSize: '1rem', marginTop: '8px' }}>{s.d}</p>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="code-box animate-on-scroll" style={{ minHeight: '320px' }}>
              <div className="code-content" key={activeStep}>
                <span className="comment">{codeSnippets[activeStep].comment}</span><br />
                {codeSnippets[activeStep].commands.map((c, i) => (
                  <div key={i} style={{ marginTop: '12px' }}>
                    <span className="cmd" style={{ fontSize: '0.8rem', opacity: 0.7 }}>$</span> <span className="cmd">{c.cmd}</span> {c.text}
                  </div>
                ))}
                <div style={{ marginTop: '40px', borderTop: '1px solid rgba(255,255,255,0.1)', paddingTop: '20px' }}>
                  <div className="ok" style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.875rem' }}>
                    <ShieldCheck size={14} /> Step {activeStep} validated
                  </div>
                  <div className="ok" style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.875rem', marginTop: '4px', opacity: 0.8 }}>
                    <Zap size={14} /> Environment ready
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="section" id="pricing">
        <div className="container">
          <div className="section-header align-center animate-on-scroll">
            <span className="tag">Public Beta</span>
            <h2>Simple, transparent pricing</h2>
            <p>During our public beta, all cloud features are free to use.</p>
          </div>

          <div className="pricing-grid">
            <article className="plan-card popular animate-on-scroll">
              <span className="plan-badge">Public Beta</span>
              <h3>Cloud Beta</h3>
              <p>Fully managed by WardSeal</p>
              <div className="plan-price"><span className="plan-amount">Free</span><span className="plan-per">/ during beta</span></div>
              <ul className="plan-features">
                <li className="plan-feature"><ShieldCheck size={18} className="check" /> Full SaaS Platform Access</li>
                <li className="plan-feature"><ShieldCheck size={18} className="check" /> Automated Backups & HA</li>
                <li className="plan-feature"><ShieldCheck size={18} className="check" /> Unlimited System-Admins</li>
                <li className="plan-feature"><ShieldCheck size={18} className="check" /> No limits during testing</li>
              </ul>
              <a className="btn btn-primary w-full" href={`${consoleBaseUrl}/signup`}>Get Started for Free</a>
            </article>

            <article className="plan-card animate-on-scroll" style={{ animationDelay: '0.1s' }}>
              <h3>Enterprise</h3>
              <p>For large-scale platforms</p>
              <div className="plan-price"><span className="plan-amount">Custom</span></div>
              <ul className="plan-features">
                <li className="plan-feature"><ShieldCheck size={18} className="check" /> Managed VPC Deployment</li>
                <li className="plan-feature"><ShieldCheck size={18} className="check" /> Custom SLAs & 24/7 Support</li>
                <li className="plan-feature"><ShieldCheck size={18} className="check" /> Advanced Governance</li>
                <li className="plan-feature"><ShieldCheck size={18} className="check" /> On-prem / Hybrid Options</li>
              </ul>
              <a className="btn btn-outline w-full" href="mailto:sales@wardseal.com">Contact Sales</a>
            </article>
          </div>
        </div>
      </section>

      <section className="section section-muted">
        <div className="container faq">
          <div className="section-header align-center animate-on-scroll">
            <span className="tag">FAQ</span>
            <h2>Common Questions</h2>
          </div>
          <div className="faq-list">
            {faqItems.map((item, idx) => (
              <div className={`faq-item ${openFaq === idx ? 'open' : ''}`} key={item.q}>
                <button className="faq-q" onClick={() => setOpenFaq(openFaq === idx ? -1 : idx)}>
                  {item.q}
                  <span className="faq-icon" style={{ transform: openFaq === idx ? 'rotate(45deg)' : 'none', transition: 'transform 0.3s' }}>+</span>
                </button>
                <div className="faq-a">
                  <div style={{ paddingBottom: '24px' }}>{item.a}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <div className="cta-glass fade-up">
            <span className="tag" style={{ marginBottom: '24px' }}>Get Started</span>
            <h2 style={{ marginBottom: '16px' }}>Secure your application today</h2>
            <p style={{ marginBottom: '32px', opacity: 0.9 }}>Join the managed cloud beta today. No credit card. No complications.</p>
            <div className="hero-cta" style={{ justifyContent: 'center' }}>
              <a className="btn btn-outline btn-lg" style={{ background: 'white', color: 'var(--primary)' }} href={`${consoleBaseUrl}/signup`}>
                Create Free Account
              </a>
              <a className="btn btn-lg" style={{ border: '1px solid rgba(255,255,255,0.3)', color: 'white' }} href="https://github.com/dhawalhost/wardseal">
                Read Documentation
              </a>
            </div>
          </div>
        </div>
      </section>
    </main>
  )
}
