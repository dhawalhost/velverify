import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');

export const options = {
  scenarios: {
    auth_journey: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '1m', target: 100 }, // Ramp up
        { duration: '3m', target: 100 }, // Stay at 100 VUs
        { duration: '1m', target: 0 },   // Ramp down
      ],
    },
  },
  thresholds: {
    'http_req_duration': ['p(95)<200'], // 95% of requests must be below 200ms
    'errors': ['rate<0.01'],            // Error rate must be under 1%
  },
};

// Configuration from environment
const BASE_URL = __ENV.BASE_URL || 'http://auth.wardseal.local';
const TENANT_SLUG = __ENV.TENANT_SLUG || 'default';
const USERNAME = __ENV.USERNAME || 'admin@example.com';
const PASSWORD = __ENV.PASSWORD || 'Password123!';
const CLIENT_ID = __ENV.CLIENT_ID || 'test-client';

export default function () {
  const jar = http.cookieJar();

  // 1. OIDC Discovery
  const discoveryRes = http.get(`${BASE_URL}/t/${TENANT_SLUG}/.well-known/openid-configuration`);
  check(discoveryRes, {
    'discovery status is 200': (r) => r.status === 200,
  }) || errorRate.add(1);

  sleep(1);

  // 2. Login (to establish session)
  const loginPayload = JSON.stringify({
    username: USERNAME,
    password: PASSWORD,
  });
  const loginHeaders = { 'Content-Type': 'application/json' };
  const loginRes = http.post(`${BASE_URL}/t/${TENANT_SLUG}/login`, loginPayload, { headers: loginHeaders });
  
  const loginCheck = check(loginRes, {
    'login status is 200': (r) => r.status === 200,
    'session token returned': (r) => r.json('token') !== undefined,
  });

  if (!loginCheck) {
    errorRate.add(1);
    return;
  }

  sleep(1);

  // 3. OAuth2 Authorize (PKCE)
  // We use redirects: 0 to capture the authorization code from the Location header
  const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'; // Pre-calculated for simplicity
  const codeChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'; // S256 challenge
  
  const authorizeUrl = `${BASE_URL}/t/${TENANT_SLUG}/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=http://localhost:5173/callback&scope=openid profile email&code_challenge=${codeChallenge}&code_challenge_method=S256`;
  
  const authorizeRes = http.get(authorizeUrl, { redirects: 0 });
  
  const authCheck = check(authorizeRes, {
    'authorize status is 302': (r) => r.status === 302,
    'redirects to callback': (r) => r.headers['Location'] && r.headers['Location'].includes('/callback'),
  });

  if (!authCheck) {
    errorRate.add(1);
    return;
  }

  // Extract code from Location header
  const location = authorizeRes.headers['Location'];
  const codeMatch = location.match(/code=([^&]+)/);
  if (!codeMatch) {
    errorRate.add(1);
    return;
  }
  const code = codeMatch[1];

  sleep(1);

  // 4. Token Exchange (PKCE)
  const tokenPayload = `grant_type=authorization_code&client_id=${CLIENT_ID}&code=${code}&redirect_uri=http://localhost:5173/callback&code_verifier=${codeVerifier}`;
  const tokenHeaders = { 'Content-Type': 'application/x-www-form-urlencoded' };
  
  const tokenRes = http.post(`${BASE_URL}/t/${TENANT_SLUG}/oauth2/token`, tokenPayload, { headers: tokenHeaders });
  
  const tokenCheck = check(tokenRes, {
    'token exchange status is 200': (r) => r.status === 200,
    'access token returned': (r) => r.json('access_token') !== undefined,
    'refresh token returned': (r) => r.json('refresh_token') !== undefined,
  });

  if (!tokenCheck) {
    errorRate.add(1);
    return;
  }

  const refreshToken = tokenRes.json('refresh_token');

  sleep(1);

  // 5. Token Refresh
  const refreshPayload = `grant_type=refresh_token&client_id=${CLIENT_ID}&refresh_token=${refreshToken}`;
  const refreshRes = http.post(`${BASE_URL}/t/${TENANT_SLUG}/oauth2/token`, refreshPayload, { headers: tokenHeaders });
  
  check(refreshRes, {
    'refresh status is 200': (r) => r.status === 200,
    'new access token returned': (r) => r.json('access_token') !== undefined,
  }) || errorRate.add(1);

  sleep(2);
}
