import { Link } from 'react-router-dom'
import siteConfig from '../siteConfig'

const { consoleBaseUrl } = siteConfig

export default function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="container">
        <div className="footer-grid">
          <div>
            <Link className="logo" to="/" style={{ marginBottom: '24px' }}>
              <div className="logo-container">
                <img src="/wardseal.svg" alt="WardSeal Logo" className="logo-img" />
              </div>
              <span className="logo-text">WardSeal</span>
            </Link>
            <div className="footer-tagline" style={{ color: 'var(--text-muted)', fontSize: '1.05rem', lineHeight: '1.6', maxWidth: '300px' }}>
              Next-generation AI Identity &amp; Access Management for modern enterprises.
            </div>
          </div>
          <div className="footer-col">
            <h4>Product</h4>
            <ul>
              <li><a href="/#features">Features</a></li>
              <li><a href="/#pricing">Pricing</a></li>
            </ul>
          </div>
          <div className="footer-col">
            <h4>Developers</h4>
            <ul>
              <li><a href="https://github.com/dhawalhost/wardseal" target="_blank" rel="noreferrer">GitHub</a></li>
              <li><Link to="/policies">Policies</Link></li>
            </ul>
          </div>
          <div className="footer-col">
            <h4>Company</h4>
            <ul>
              <li><Link to="/privacy-policy">Privacy Policy</Link></li>
              <li><Link to="/terms-of-service">Terms of Service</Link></li>
              <li><Link to="/cookies">Cookie Policy</Link></li>
            </ul>
          </div>
        </div>
        <div className="footer-bottom">
          <span>© {new Date().getFullYear()} WardSeal. All rights reserved.</span>
          <span>Built on open standards — OIDC · SAML · SCIM · WebAuthn</span>
        </div>
      </div>
    </footer>
  )
}
