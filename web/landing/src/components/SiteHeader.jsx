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
          <img src="/wardseal.svg" alt="WardSeal Logo" className="logo-img" />
          WardSeal
        </Link>

        {/* Mobile Toggle */}
        <button className="mobile-toggle" onClick={toggleMenu} aria-label="Toggle Menu">
          {isMenuOpen ? <X size={24} /> : <Menu size={24} />}
        </button>

        <nav className={`nav-links ${isMenuOpen ? 'active' : ''}`}>
          <a href="/#features" onClick={closeMenu}>Features</a>
          <a href="/#pricing" onClick={closeMenu}>Pricing</a>
          <Link to="/policies" className={pathname === '/policies' ? 'active' : ''} onClick={closeMenu}>Policies</Link>
          <a href="https://github.com/dhawalhost/wardseal" target="_blank" rel="noreferrer" onClick={closeMenu}>Docs</a>
          
          {/* Mobile Only Actions */}
          <div className="mobile-actions">
            <a className="btn btn-outline btn-sm" href={`${consoleBaseUrl}/login`}>Sign In</a>
            <a className="btn btn-primary btn-sm" href={`${consoleBaseUrl}/signup`}>Get Started</a>
          </div>
        </nav>

        <div className="header-actions">
          <a className="btn btn-outline btn-sm" href={`${consoleBaseUrl}/login`}>Sign In</a>
          <a className="btn btn-primary btn-sm" href={`${consoleBaseUrl}/signup`}>Get Started</a>
        </div>
      </div>
    </header>
  )
}
