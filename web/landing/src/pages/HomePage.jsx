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
  const [yearly, setYearly] = useState(false)
  const [openFaq, setOpenFaq] = useState(0)

  const proPrice = yearly ? pricing.yearly.pro : pricing.monthly.pro
  const teamPrice = yearly ? pricing.yearly.team : pricing.monthly.team

  const codeSnippets = {
    1: {
      comment: "# Initialize Cloud Tenant",
      commands: [
        { cmd: "wardseal", text: "login --domain cloud.wardseal.com" },
        { cmd: "wardseal", text: 'tenant create --name "HighGrowth Inc"' }
      ]
    },
    2: {
      comment: "# Register OIDC Application",
      commands: [
        { cmd: "wardseal", text: 'apps create --name "Production App" \\' },
        { cmd: "", text: '  --type "oidc" --redirect-uri "https://app.com/callback"' }
      ]
    },
    3: {
      comment: "# Configuration & Discovery",
      commands: [
        { cmd: "curl", text: "https://cloud.wardseal.com/auth/.well-known/openid-configuration" },
        { cmd: "wardseal", text: "policies create --file prod-security.yaml" }
      ]
    }
  };

  useEffect(() => {
    const handleMouseMove = (e) => {
      const cards = document.querySelectorAll('.feature-card');
      cards.forEach(card => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        card.style.setProperty('--mouse-x', `${x}px`);
        card.style.setProperty('--mouse-y', `${y}px`);
      });
    };

    window.addEventListener('mousemove', handleMouseMove);

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(e => { 
        if (e.isIntersecting) { 
          e.target.classList.add('fade-up'); 
          observer.unobserve(e.target); 
        } 
      });
    }, { threshold: 0.1 });

    document.querySelectorAll('.animate-on-scroll').forEach(el => observer.observe(el));
    return () => {
      observer.disconnect();
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, []);

  return (
    <main>
      <section className="hero">
        <div className="container hero-content fade-up">
          <div className="hero-text">
            <span className="tag"><Zap className="w-3 h-3" /> Public Beta — Cloud Managed</span>
            <h1 style={{ marginTop: '24px' }}>
              Identity Infrastructure for <br/>
              <span className="gradient-text">Cloud-Native Teams</span>
            </h1>
            <p style={{ fontSize: '1.4rem', marginTop: '32px' }}>
              The modern standard for AuthN, AuthZ, and Governance. <br/>
              Built for performance. Designed for developers.
            </p>
            <div className="hero-cta" style={{ justifyContent: 'flex-start', marginTop: '40px' }}>
              <a className="btn btn-primary btn-lg" href={`${consoleBaseUrl}/signup?plan=free`}>
                Start Building Free <ArrowRight className="w-4 h-4 ml-2" />
              </a>
              {/* <a className="btn btn-outline btn-lg" href="https://github.com/dhawalhost/wardseal" target="_blank" rel="noreferrer">
                <Star className="w-4 h-4 mr-2" /> GitHub
              </a> */}
            </div>
            
            <div className="hero-trust mt-12 flex items-center gap-6 opacity-60 grayscale hover:grayscale-0 transition-all duration-500" style={{ marginTop: '64px', display: 'flex', alignItems: 'center', gap: '32px' }}>
              <span style={{ fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Secure by Default</span>
              <div style={{ display: 'flex', gap: '24px', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.9rem' }}><Lock className="w-4 h-4" /> SHA-256</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.9rem' }}><ShieldCheck className="w-4 h-4" /> OIDC/SAML</div>
              </div>
            </div>
          </div>
          <div className="hero-mockup">
            <div className="mockup-container glass" style={{ padding: '8px', borderRadius: 'var(--r-lg)', background: 'rgba(255,255,255,0.05)' }}>
               <img src="/console-preview.png" alt="WardSeal Console Preview" className="mockup-img" style={{ transform: 'none', borderRadius: 'var(--r)' }} />
               <div className="absolute -bottom-6 -left-6 glass p-4 rounded-xl hidden lg:block" style={{ position: 'absolute', bottom: '-24px', left: '-24px', padding: '16px', borderRadius: 'var(--r)' }}>
                 <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                   <div style={{ width: '40px', height: '40px', background: 'var(--primary)', borderRadius: 'var(--r)', display: 'flex', alignItems: 'center', justifyItems: 'center', justifyContent: 'center' }}>
                     <Fingerprint className="text-white w-6 h-6" />
                   </div>
                   <div>
                     <div style={{ fontSize: '0.8rem', fontWeight: 700 }}>Passkey Active</div>
                     <div style={{ fontSize: '0.7rem', opacity: 0.6 }}>Biometric verified</div>
                   </div>
                 </div>
               </div>
            </div>
          </div>
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
                <h3 style={{ fontSize: '1.5rem', marginBottom: '16px' }}>{f.title}</h3>
                <p style={{ fontSize: '1rem', lineHeight: '1.7' }}>{f.desc}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="section section-muted">
        <div className="container">
          <div className="how-grid">
            <div className="how-text">
              <span className="tag mb-4">Quick Start</span>
              <h2 className="mb-8">Up and running in minutes</h2>
              <div className="steps">
                {[
                  { n: 1, t: 'Create your account', d: 'Sign up for free. Your tenant is provisioned instantly.' },
                  { n: 2, t: 'Connect your app', d: 'Register an OIDC/OAuth app. Copy the client ID.' },
                  { n: 3, t: 'Configure SSO & MFA', d: 'Enable social login or passkeys in a few clicks.' }
                ].map(s => (
                  <div 
                    className={`step cursor-pointer transition-all duration-300 ${activeStep === s.n ? 'opacity-100 scale-105' : 'opacity-50'}`} 
                    key={s.n}
                    onMouseEnter={() => setActiveStep(s.n)}
                    style={{ cursor: 'pointer' }}
                  >
                    <div className={`step-num ${activeStep === s.n ? 'glow-blue' : ''}`}>{s.n}</div>
                    <div className="step-content">
                      <h3 className="step-title" style={{ color: activeStep === s.n ? 'var(--text)' : 'var(--text-muted)' }}>{s.t}</h3>
                      <p className="step-desc" style={{ display: activeStep === s.n ? 'block' : 'none' }}>{s.d}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="code-box animate-on-scroll glass" style={{ minHeight: '300px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <div className="code-content fade-up" key={activeStep}>
                <span className="comment">{codeSnippets[activeStep].comment}</span><br />
                {codeSnippets[activeStep].commands.map((c, i) => (
                  <div key={i} style={{ marginTop: '8px' }}>
                    <span className="cmd">{c.cmd}</span> {c.text}
                  </div>
                ))}
                <div style={{ marginTop: '32px' }}>
                  <span className="ok" style={{ opacity: 0.8 }}>✓ Step {activeStep} validated</span><br />
                  <span className="ok" style={{ opacity: 0.8 }}>✓ Environment ready</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>


      <section className="section section-muted" id="pricing">
        <div className="container">
          <div className="section-header align-center">
            <span className="tag">Public Beta</span>
            <h2>Simple, transparent pricing</h2>
            <p>During our public beta, all cloud features are free to use.</p>
          </div>

          <div className="pricing-grid" style={{ marginTop: '60px' }}>
            <article className="plan-card popular animate-on-scroll">
              <span className="plan-badge">Public Beta</span>
              <h3 className="plan-name">Cloud Beta</h3>
              <p className="plan-desc">Fully managed by WardSeal</p>
              <div className="plan-price"><span className="plan-amount">Free</span><span className="plan-per">/for beta testers</span></div>
              <ul className="plan-features">
                <li className="plan-feature"><span className="check">✓</span> Full SaaS Platform Access</li>
                <li className="plan-feature"><span className="check">✓</span> Automated Backups & HA</li>
                <li className="plan-feature"><span className="check">✓</span> **Unlimited System-Admins**</li>
                <li className="plan-feature"><span className="check">✓</span> **No limits during testing phase**</li>
              </ul>
              <a className="btn btn-primary w-full" href={`${consoleBaseUrl}/signup?plan=beta`}>Get Started for Free</a>
            </article>

            <article className="plan-card animate-on-scroll">
              <h3 className="plan-name">Enterprise</h3>
              <p className="plan-desc">For large-scale platforms</p>
              <div className="plan-price"><span className="plan-amount">Coming Soon</span></div>
              <ul className="plan-features">
                <li className="plan-feature"><span className="check">✓</span> Managed VPC Deployment</li>
                <li className="plan-feature"><span className="check">✓</span> Custom SLAs & 24/7 Support</li>
                <li className="plan-feature"><span className="check">✓</span> Advanced Identity Governance</li>
                <li className="plan-feature"><span className="check">✓</span> **On-prem / Hybrid Options**</li>
              </ul>
              <a className="btn btn-outline w-full" href="mailto:sales@wardseal.com">Contact for Early Access</a>
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
          <div className="faq-list">
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
        <div className="container text-center">
          <div className="cta-glass glass" style={{ padding: '80px 48px', borderRadius: 'var(--r-lg)' }}>
            <span className="tag mb-4">Get Started</span>
            <h2 className="mb-4">Secure your application today</h2>
            <p className="cta-desc">Join the managed cloud beta today. No credit card. No complications.</p>
            <div className="hero-cta" style={{ marginTop: '32px' }}>
              <a className="btn btn-primary" href={`${consoleBaseUrl}/signup`}>Create Free Account &rarr;</a>
              <a className="btn btn-outline" href="https://github.com/dhawalhost/wardseal">Read the Docs</a>
            </div>
          </div>
        </div>
      </section>
    </main>
  )
}
