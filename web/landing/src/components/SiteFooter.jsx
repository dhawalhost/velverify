import { Link } from 'react-router-dom'
import siteConfig from '../siteConfig'

const { consoleBaseUrl } = siteConfig

export default function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="container">
        <div className="footer-grid">
          <div>
            <Link className="logo-dot" to="/">
              <img src="/wardseal.svg" alt="WardSeal Logo" className="logo-img" />
            </Link>
            <div className="footer-tagline">Open-source Identity &amp; Access Management for the modern cloud.</div>
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
              <li><Link to="/privacy">Privacy Policy</Link></li>
              <li><Link to="/terms">Terms of Service</Link></li>
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
