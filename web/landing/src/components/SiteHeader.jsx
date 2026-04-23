import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Menu, X } from 'lucide-react'
import siteConfig from '../siteConfig'

const { consoleBaseUrl } = siteConfig

export default function SiteHeader() {
  const { pathname } = useLocation()
  const [isMenuOpen, setIsMenuOpen] = useState(false)

  const toggleMenu = () => setIsMenuOpen(!isMenuOpen)
  const closeMenu = () => setIsMenuOpen(false)

  return (
    <header className={`site-header ${isMenuOpen ? 'menu-open' : ''}`}>
      <div className="container header-inner">
        <Link className="logo" to="/" onClick={closeMenu}>
          <div className="logo-container">
            <img src="/wardseal.svg" alt="WardSeal Logo" className="logo-img" />
          </div>
          <span className="logo-text">WardSeal</span>
        </Link>

        {/* Mobile Toggle */}
        <button className="mobile-toggle" onClick={toggleMenu} aria-label="Toggle Menu">
          {isMenuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>

        <nav className={`nav-links ${isMenuOpen ? 'active' : ''}`}>
          <a href="/#features" onClick={closeMenu}>Features</a>
          <a href="/#pricing" onClick={closeMenu}>Pricing</a>
          <Link to="/policies" className={pathname === '/policies' ? 'active' : ''} onClick={closeMenu}>Policies</Link>
          <a href="https://github.com/dhawalhost/wardseal" target="_blank" rel="noreferrer" onClick={closeMenu}>Docs</a>
        </nav>

        <div className="header-actions">
          {localStorage.getItem('token') ? (
            <Link className="btn btn-primary btn-sm" to={`${consoleBaseUrl}/portal`}>
              Go to Portal
            </Link>
          ) : (
            <>
              <a className="btn-text" href={`${consoleBaseUrl}/login`}>Sign in</a>
              <a className="btn btn-primary btn-sm btn-glow" href={`${consoleBaseUrl}/signup`}>Get Started</a>
            </>
          )}
        </div>
      </div>
    </header>
  )
}
