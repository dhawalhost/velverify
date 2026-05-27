import { useEffect } from 'react'
import {
  ShieldCheck, Lock, Terminal,
  ArrowRight, Github, Activity, Shield, Network,
  Server, Key, Command
} from 'lucide-react'
import siteConfig from '../siteConfig'

const { consoleBaseUrl } = siteConfig

const archFeatures = [
  {
    icon: <Terminal size={24} />,
    title: 'API-First Design',
    desc: 'Integrate authorization natively into your microservices via gRPC or REST. Headless by default, UI optional.',
    details: [
      { icon: <Command size={14} />, text: 'CLI & Terraform Provider' },
      { icon: <Activity size={14} />, text: '<10ms p99 latency' }
    ]
  },
  {
    icon: <Lock size={24} />,
    title: 'Granular Access Management',
    desc: 'Define context-aware, attribute-based policies (ABAC) and fine-grained RBAC that evaluate at the edge.',
    details: [
      { icon: <Key size={14} />, text: 'Dynamic policy evaluation' },
      { icon: <Shield size={14} />, text: 'Risk-based step-up MFA' }
    ]
  },
  {
    icon: <Network size={24} />,
    title: 'Zero-Trust Security',
    desc: 'Verify explicitly. Deny by default. Every internal and external request is authenticated and authorized.',
    details: [
      { icon: <ShieldCheck size={14} />, text: 'Continuous Access Evaluation' },
      { icon: <Server size={14} />, text: 'Stateless JWT/PASETO validation' }
    ]
  }
]

const integrations = [
  'Okta', 'Azure AD', 'Google Workspace', 'Keycloak', 'Ping Identity', 'Auth0', 'AWS IAM', 'HashiCorp Vault'
]

export default function HomePage() {
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add('in-view')
            observer.unobserve(e.target)
          }
        })
      },
      { threshold: 0.1 }
    )
    document.querySelectorAll('.reveal').forEach((el) => observer.observe(el))
    return () => observer.disconnect()
  }, [])

  return (
    <main>
      {/* ── HERO ── */}
      <section className="hero">
        <div className="container hero-content">
          <div className="hero-text reveal">
            <div className="tag">
              <Lock size={14} /> Zero-Trust Access Control
            </div>
            <h1>
              Trust Nothing.<br />
              Verify Everything.
            </h1>
            <p className="hero-subtitle">
              Open-source identity governance with zero-trust access control, API-first architecture, and granular authorization — built for engineers who ship secure infrastructure.
            </p>
            <div className="hero-cta">
              <a className="btn btn-accent btn-lg" href={`${consoleBaseUrl}/signup`}>
                Deploy Now <ArrowRight size={18} />
              </a>
              <a className="btn btn-outline btn-lg" href="https://github.com/dhawalhost/wardseal">
                <Github size={18} /> View on GitHub
              </a>
            </div>
            <div className="hero-trust">
              <div className="trust-indicator"><ShieldCheck size={16} /> SOC 2 Type II</div>
              <div className="trust-dot" />
              <div className="trust-indicator"><Lock size={16} /> AES-256-GCM</div>
              <div className="trust-dot" />
              <div className="trust-indicator"><Network size={16} /> SCIM 2.0</div>
            </div>
          </div>

          <div className="hero-visual reveal" style={{ transitionDelay: '150ms' }}>
            <div className="hero-image-wrapper">
              <img src="/hero-monolith.png" alt="WardSeal Zero Trust Architecture" className="hero-img" />
            </div>
          </div>
        </div>
      </section>

      {/* ── INTEGRATIONS MARQUEE ── */}
      <section className="integrations-bar">
        <div className="integrations-label">Native Identity Federation</div>
        <div className="marquee-track">
          {[...integrations, ...integrations, ...integrations].map((name, i) => (
            <div className="integration-item" key={i}>
              <Network size={16} /> {name}
            </div>
          ))}
        </div>
      </section>

      {/* ── ARCHITECTURE GRID ── */}
      <section className="section" id="features">
        <div className="container">
          <div className="section-header align-center reveal">
            <h2>Built for Modern Infrastructure</h2>
            <p>Seamlessly integrate enterprise-grade security without compromising on developer velocity or system latency.</p>
          </div>
          <div className="arch-grid">
            {archFeatures.map((f, i) => (
              <article
                className="arch-card reveal"
                key={i}
                style={{ transitionDelay: `${i * 100}ms` }}
              >
                <div className="arch-icon">{f.icon}</div>
                <h3>{f.title}</h3>
                <p>{f.desc}</p>
                <div className="arch-details">
                  {f.details.map((d, j) => (
                    <div className="arch-detail" key={j}>
                      {d.icon} {d.text}
                    </div>
                  ))}
                </div>
              </article>
            ))}
          </div>
        </div>
      </section>

      {/* ── CODE PREVIEW ── */}
      <section className="section section-muted">
        <div className="container">
          <div className="code-section">
            <div className="code-text reveal">
              <div className="tag"><Terminal size={14} /> Developer First</div>
              <h2>Drop-in Authorization Middleware</h2>
              <p>Secure your Go microservices in minutes. WardSeal evaluates policies at the edge with sub-millisecond overhead, entirely stateless.</p>
              <div className="code-highlights">
                <div className="code-highlight">
                  <ShieldCheck size={18} />
                  <span>Automatically verifies incoming JWT or PASETO tokens against the WardSeal JWKS endpoint.</span>
                </div>
                <div className="code-highlight">
                  <Lock size={18} />
                  <span>Evaluates contextual ABAC policies before the request reaches your core business logic.</span>
                </div>
              </div>
            </div>
            
            <div className="code-block reveal" style={{ transitionDelay: '150ms' }}>
              <div className="code-block-header">
                <div className="code-block-dots"><span /><span /><span /></div>
                <div className="code-block-filename">middleware/authz.go</div>
              </div>
              <div className="code-block-body">
<pre><code><span className="tok-keyword">func</span> <span className="tok-func">AuthzMiddleware</span>(<span className="tok-param">policy</span> <span className="tok-type">wardseal.Policy</span>) <span className="tok-keyword">func</span>(<span className="tok-type">http.Handler</span>) <span className="tok-type">http.Handler</span> {'{'}
    <span className="tok-keyword">return</span> <span className="tok-keyword">func</span>(<span className="tok-param">next</span> <span className="tok-type">http.Handler</span>) <span className="tok-type">http.Handler</span> {'{'}
        <span className="tok-keyword">return</span> <span className="tok-type">http.HandlerFunc</span>(<span className="tok-keyword">func</span>(<span className="tok-param">w</span> <span className="tok-type">http.ResponseWriter</span>, <span className="tok-param">r</span> *<span className="tok-type">http.Request</span>) {'{'}
            <span className="tok-comment">// 1. Validate Token</span>
            <span className="tok-var">claims</span>, <span className="tok-var">err</span> := <span className="tok-builtin">wardseal</span>.<span className="tok-method">VerifyToken</span>(<span className="tok-var">r</span>)
            <span className="tok-keyword">if</span> <span className="tok-var">err</span> != <span className="tok-nil">nil</span> {'{'}
                <span className="tok-builtin">http</span>.<span className="tok-method">Error</span>(<span className="tok-var">w</span>, <span className="tok-string">"unauthorized"</span>, <span className="tok-builtin">http</span>.<span className="tok-var">StatusUnauthorized</span>)
                <span className="tok-keyword">return</span>
            {'}'}

            <span className="tok-comment">// 2. Evaluate Policy</span>
            <span className="tok-keyword">if</span> !<span className="tok-var">policy</span>.<span className="tok-method">Evaluate</span>(<span className="tok-var">claims</span>, <span className="tok-var">r</span>) {'{'}
                <span className="tok-builtin">http</span>.<span className="tok-method">Error</span>(<span className="tok-var">w</span>, <span className="tok-string">"forbidden"</span>, <span className="tok-builtin">http</span>.<span className="tok-var">StatusForbidden</span>)
                <span className="tok-keyword">return</span>
            {'}'}

            <span className="tok-comment">// 3. Proceed</span>
            <span className="tok-var">next</span>.<span className="tok-method">ServeHTTP</span>(<span className="tok-var">w</span>, <span className="tok-var">r</span>)
        {'}'})
    {'}'}
{'}'}</code></pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── CTA BANNER ── */}
      <section className="section">
        <div className="container">
          <div className="cta-banner reveal">
            <h2>Ready to secure your infrastructure?</h2>
            <p>Join the open-source community or deploy the enterprise platform in your environment.</p>
            <div className="cta-actions">
              <a className="btn btn-accent btn-lg" href={`${consoleBaseUrl}/signup`}>
                Start Building <ArrowRight size={18} />
              </a>
              <a className="btn btn-outline btn-lg" href="https://github.com/dhawalhost/wardseal">
                Read the Docs
              </a>
            </div>
          </div>
        </div>
      </section>
    </main>
  )
}
