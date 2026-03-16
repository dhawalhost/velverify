import React from 'react';
import { ChevronLeft } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function PolicyLayout({ title, lastUpdated, children }) {
  return (
    <main className="policy-page">
      <section className="section">
        <div className="container" style={{ maxWidth: '800px' }}>
          <div style={{ marginBottom: '40px' }}>
            <Link to="/policies" className="btn-link" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', color: 'var(--text-dim)', textDecoration: 'none', fontSize: '0.9rem' }}>
              <ChevronLeft size={16} /> Back to Policies
            </Link>
          </div>
          
          <div className="section-header" style={{ marginBottom: '48px' }}>
            <span className="tag">Legal</span>
            <h1 style={{ fontSize: '2.5rem', marginBottom: '16px' }}>{title}</h1>
            {lastUpdated && (
              <p style={{ color: 'var(--text-dim)', fontSize: '0.9rem' }}>
                Effective Date: {lastUpdated}
              </p>
            )}
          </div>

          <div className="policy-content" style={{ color: 'var(--text-muted)', lineHeight: '1.7' }}>
            {children}
          </div>
          
          <div style={{ marginTop: '60px', padding: '40px', background: 'var(--primary-surface)', borderRadius: 'var(--r-md)', border: '1px solid var(--border)' }}>
            <h3>Questions about our policies?</h3>
            <p style={{ marginBottom: '20px' }}>Our legal and privacy teams are here to help you understand how WardSeal protects your data and your rights.</p>
            <a href="mailto:privacy@wardseal.com" className="btn btn-primary">Contact Privacy Team</a>
          </div>
        </div>
      </section>
    </main>
  );
}
