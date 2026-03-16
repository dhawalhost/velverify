import { Link, useLocation } from 'react-router-dom'
import siteConfig from '../siteConfig'

const { consoleBaseUrl, helpBaseUrl } = siteConfig

export default function SiteHeader() {
  const { pathname } = useLocation()

  return (
    <header className="site-header">
      <div className="container header-inner">
        <Link className="logo" to="/">
          <img src="/wardseal.svg" alt="WardSeal Logo" className="logo-img" />
          WardSeal
        </Link>

        <nav className="nav-links">
          <a href="/#features">Features</a>
          <a href="/#pricing">Pricing</a>
          <Link to="/policies" className={pathname === '/policies' ? 'active' : ''}>Policies</Link>
          <a href="https://github.com/dhawalhost/wardseal" target="_blank" rel="noreferrer">Docs</a>
        </nav>

        <div className="header-actions">
          <Link className="btn btn-outline btn-sm" to="/policies">Policies</Link>
          <a className="btn btn-outline btn-sm" href={`${consoleBaseUrl}/login`}>Sign In</a>
          <a className="btn btn-primary btn-sm" href={`${consoleBaseUrl}/signup`}>Get Started</a>
        </div>
      </div>
    </header>
  )
}
