import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Menu, X, Github } from 'lucide-react'
import siteConfig from '../siteConfig'

const { consoleBaseUrl } = siteConfig

export default function SiteHeader() {
  const { pathname } = useLocation()
  const [isMenuOpen, setIsMenuOpen] = useState(false)

  const toggleMenu = () => setIsMenuOpen(!isMenuOpen)
  const closeMenu = () => setIsMenuOpen(false)

  return (
    <header className="site-header">
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
          <Link to="/policies" className={pathname === '/policies' ? 'active' : ''} onClick={closeMenu}>Policies</Link>
          <a href="https://github.com/dhawalhost/wardseal" target="_blank" rel="noreferrer" onClick={closeMenu}>
             Documentation
          </a>
          <div className="header-actions" style={isMenuOpen ? { marginTop: '16px', display: 'flex', flexDirection: 'column', alignItems: 'stretch' } : {}}>
            {localStorage.getItem('token') ? (
              <a className="btn btn-accent btn-sm" href={`${consoleBaseUrl}/portal`}>
                Go to Console
              </a>
            ) : (
              <>
                <a className="btn-text" href={`${consoleBaseUrl}/login`}>Log In</a>
                <a className="btn btn-accent btn-sm" href={`${consoleBaseUrl}/signup`}>Deploy Now</a>
              </>
            )}
          </div>
        </nav>
      </div>
    </header>
  )
}
