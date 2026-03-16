import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const successCount = new Counter('success_count');

export const options = {
  scenarios: {
    // Stage 1: Morning Rush - gradual ramp up to 1000 users over 1 min
    morning_rush: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 500 },
        { duration: '1m', target: 500 },
        { duration: '30s', target: 0 },
      ],
      gracefulRampDown: '10s',
    },
  },
  thresholds: {
    // Assertions
    'http_req_duration': ['p(95)<250'], // 95% of requests should be below 250ms
    'errors': ['rate<0.01'],            // Error rate must be under 1%
  },
};

const BASE_URL = __ENV.AUTH_SERVICE_URL || 'http://localhost:8080';

export default function () {
  // 1. Fetch OpenID Discovery document (simulate a relying party booting up)
  const discoveryRes = http.get(`${BASE_URL}/.well-known/openid-configuration`);
  
  const discoveryCheck = check(discoveryRes, {
    'discovery status is 200': (r) => r.status === 200,
  });
  
  if (!discoveryCheck) {
    errorRate.add(1);
    return;
  }

  // Randomize realistic think time
  sleep(Math.random() * 2);

  // 2. Simulate requesting an Authorization code (login page load)
  const authorizeRes = http.get(`${BASE_URL}/oauth2/authorize?client_id=test-client&response_type=code&redirect_uri=http://localhost:5173/callback&scope=openid profile email`);
  
  const authCheck = check(authorizeRes, {
    'authorize endpoint reachable': (r) => r.status === 200 || r.status === 302, // Could be immediate redirect if session exists, else 200 for login UI
  });

  if (!authCheck) {
    errorRate.add(1);
    return;
  }

  successCount.add(1);
  sleep(1);
}
