/**
 * WardSeal Login Widget
 * A drop-in authentication widget for web apps.
 * 
 * Usage:
 *   <script src="https://your-domain/widget/wardseal-login.js"></script>
 *   <div id="wardseal-login"></div>
 *   <script>
 *     WardSeal.init({
 *       container: '#wardseal-login',
 *       tenantId: 'your-tenant-id',
 *       clientId: 'your-client-id',
 *       redirectUri: 'https://your-app/callback',
 *       onSuccess: (token) => { console.log('Logged in!', token); }
 *     });
 *   </script>
 */

(function(window) {
  'use strict';

  const STYLES = `
    .vv-widget {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      max-width: 360px;
      margin: 0 auto;
      padding: 2rem;
      background: #09090b;
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
      color: #fafafa;
    }
    .vv-widget h2 {
      margin: 0 0 1.5rem;
      text-align: center;
      color: #fafafa;
      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .vv-widget input {
      width: 100%;
      padding: 0.75rem 1rem;
      margin-bottom: 1rem;
      background: rgba(24, 24, 27, 0.7);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 8px;
      color: #fafafa;
      font-size: 1rem;
      box-sizing: border-box;
    }
    .vv-widget input:focus {
      outline: none;
      border-color: #06ffa5;
      box-shadow: 0 0 0 3px rgba(6,255,165,0.25);
    }
    .vv-widget button {
      width: 100%;
      padding: 0.85rem;
      background: #06ffa5;
      color: #09090b;
      border: 1px solid #06ffa5;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 700;
      cursor: pointer;
      transition: background 0.2s, box-shadow 0.2s;
    }
    .vv-widget button:hover { 
      background: #00e896; 
      box-shadow: 0 0 20px rgba(6,255,165,0.25);
    }
    .vv-widget button:disabled { 
      background: #18181b; 
      color: #71717a;
      border-color: #27272a;
      cursor: not-allowed; 
      box-shadow: none;
    }
    .vv-widget .vv-error {
      padding: 0.75rem;
      background: rgba(239, 68, 68, 0.1);
      color: #ef4444;
      border: 1px solid rgba(239, 68, 68, 0.2);
      border-radius: 8px;
      margin-bottom: 1rem;
      font-size: 0.9rem;
    }
    .vv-widget .vv-divider {
      text-align: center;
      margin: 1rem 0;
      color: #71717a;
      font-size: 0.85rem;
    }
    .vv-widget .vv-social {
      display: flex;
      gap: 0.5rem;
      margin-top: 1rem;
    }
    .vv-widget .vv-social button {
      flex: 1;
      padding: 0.6rem;
      font-size: 0.9rem;
      background: rgba(255,255,255,0.04);
      color: #fafafa;
      border: 1px solid rgba(255,255,255,0.12);
    }
    .vv-widget .vv-social button:hover {
      background: rgba(255,255,255,0.08);
      box-shadow: none;
    }
    .vv-widget .vv-google { }
    .vv-widget .vv-github { }
    .vv-widget .vv-mfa {
      margin-top: 1rem;
    }
    .vv-widget .vv-mfa input {
      text-align: center;
      letter-spacing: 0.5rem;
      font-size: 1.5rem;
    }
    .vv-widget .vv-powered {
      text-align: center;
      margin-top: 1.5rem;
      font-size: 0.75rem;
      color: #71717a;
    }
  `;

  class WardSealWidget {
    constructor(options) {
      this.options = {
        container: '#wardseal-login',
        baseUrl: window.location.origin,
        tenantId: '',
        clientId: '',
        redirectUri: '',
        onSuccess: () => {},
        onError: () => {},
        branding: { primaryColor: '#06ffa5', logoUrl: null },
        ...options
      };
      this.state = { mfaRequired: false, pendingToken: '', userId: '', loading: false, error: '' };
    }

    init() {
      const container = document.querySelector(this.options.container);
      if (!container) {
        console.error('WardSeal: Container not found:', this.options.container);
        return;
      }
      
      // Inject styles
      if (!document.getElementById('vv-styles')) {
        const styleEl = document.createElement('style');
        styleEl.id = 'vv-styles';
        styleEl.textContent = STYLES;
        document.head.appendChild(styleEl);
      }
      
      this.container = container;
      this.render();
    }

    render() {
      if (this.state.mfaRequired) {
        this.renderMFA();
      } else {
        this.renderLogin();
      }
    }

    renderLogin() {
      this.container.innerHTML = `
        <div class="vv-widget">
          ${this.options.branding.logoUrl ? `<img src="${this.options.branding.logoUrl}" alt="Logo" style="display:block;margin:0 auto 1rem;max-height:50px;">` : ''}
          <h2>Sign In</h2>
          ${this.state.error ? `<div class="vv-error">${this.state.error}</div>` : ''}
          <form id="vv-login-form">
            <input type="email" id="vv-email" placeholder="Email" required>
            <input type="password" id="vv-password" placeholder="Password" required>
            <button type="submit" ${this.state.loading ? 'disabled' : ''}>
              ${this.state.loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>
          <div class="vv-divider">or continue with</div>
          <div class="vv-social">
            <button class="vv-google" onclick="WardSeal.socialLogin('google')">Google</button>
            <button class="vv-github" onclick="WardSeal.socialLogin('github')">GitHub</button>
          </div>
          <div class="vv-powered">Secured by WardSeal</div>
        </div>
      `;
      
      document.getElementById('vv-login-form').addEventListener('submit', (e) => {
        e.preventDefault();
        this.handleLogin();
      });
    }

    renderMFA() {
      this.container.innerHTML = `
        <div class="vv-widget">
          <h2>🔐 Two-Factor Authentication</h2>
          ${this.state.error ? `<div class="vv-error">${this.state.error}</div>` : ''}
          <p style="text-align:center;color:#666;margin-bottom:1rem;">Enter the 6-digit code from your authenticator app</p>
          <form id="vv-mfa-form" class="vv-mfa">
            <input type="text" id="vv-totp" placeholder="000000" maxlength="6" required>
            <button type="submit" ${this.state.loading ? 'disabled' : ''}>
              ${this.state.loading ? 'Verifying...' : 'Verify'}
            </button>
          </form>
          <button onclick="WardSeal.cancelMFA()" style="margin-top:1rem;background:transparent;border:1px solid rgba(255,255,255,0.12);color:#fafafa;">Back to Login</button>
        </div>
      `;
      
      document.getElementById('vv-mfa-form').addEventListener('submit', (e) => {
        e.preventDefault();
        this.handleMFA();
      });
    }

    async handleLogin() {
      const email = document.getElementById('vv-email').value;
      const password = document.getElementById('vv-password').value;
      
      this.state.loading = true;
      this.state.error = '';
      this.render();

      try {
        const res = await fetch(`${this.options.baseUrl}/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Tenant-ID:': this.options.tenantId,
          },
          body: JSON.stringify({ username: email, password }),
        });
        
        const data = await res.json();
        
        if (data.mfa_required) {
          this.state.mfaRequired = true;
          this.state.pendingToken = data.pending_token;
          this.state.userId = data.user_id;
        } else if (data.token) {
          this.options.onSuccess(data.token);
        } else {
          throw new Error(data.error_description || data.error || 'Login failed');
        }
      } catch (err) {
        this.state.error = err.message;
        this.options.onError(err);
      } finally {
        this.state.loading = false;
        this.render();
      }
    }

    async handleMFA() {
      const totpCode = document.getElementById('vv-totp').value;
      
      this.state.loading = true;
      this.state.error = '';
      this.render();

      try {
        const res = await fetch(`${this.options.baseUrl}/login/mfa`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Tenant-ID': this.options.tenantId,
          },
          body: JSON.stringify({
            pending_token: this.state.pendingToken,
            totp_code: totpCode,
            user_id: this.state.userId,
          }),
        });
        
        const data = await res.json();
        
        if (data.token) {
          this.options.onSuccess(data.token);
        } else {
          throw new Error(data.error || 'Invalid TOTP code');
        }
      } catch (err) {
        this.state.error = err.message;
        this.options.onError(err);
      } finally {
        this.state.loading = false;
        this.render();
      }
    }

    cancelMFA() {
      this.state.mfaRequired = false;
      this.state.pendingToken = '';
      this.state.userId = '';
      this.state.error = '';
      this.render();
    }

    socialLogin(provider) {
      // In a real implementation, this would redirect to OAuth flow
      alert(`${provider} login coming soon!`);
    }
  }

  // Expose globally
  let instance = null;
  window.WardSeal = {
    init: function(options) {
      instance = new WardSealWidget(options);
      instance.init();
      return instance;
    },
    socialLogin: function(provider) {
      if (instance) instance.socialLogin(provider);
    },
    cancelMFA: function() {
      if (instance) instance.cancelMFA();
    }
  };

})(window);
