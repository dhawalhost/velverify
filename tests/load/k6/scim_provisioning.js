import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate } from 'k6/metrics';
import { randomString } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Custom metrics
const errorRate = new Rate('errors');
const userCreatedCount = new Counter('users_created');

export const options = {
  scenarios: {
    // Stage 1: Consistent upstream synchronization
    scim_sync: {
      executor: 'constant-vus',
      vus: 50, // 50 concurrent SCIM sync threads
      duration: '1m',
    },
  },
  thresholds: {
    // SCIM creates involve database writes, so keeping p95 under 400ms is standard
    'http_req_duration': ['p(95)<400'], 
    'errors': ['rate<0.05'], // Max 5% failure rate
  },
};

const BASE_URL = __ENV.DIR_SERVICE_URL || 'http://localhost:8081';
const AUTH_TOKEN = __ENV.SERVICE_AUTH_TOKEN || 'dev-internal-token';
const AUTH_HEADER = __ENV.SERVICE_AUTH_HEADER || 'X-Service-Auth';

export default function () {
  const headers = {
    'Content-Type': 'application/scim+json',
  };
  headers[AUTH_HEADER] = AUTH_TOKEN;

  // 1. Generate unique user payload
  const username = `loadtest_${randomString(8)}@example.com`;
  const payload = JSON.stringify({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: username,
    name: {
      familyName: "Test",
      givenName: "Load"
    },
    active: true
  });

  // 2. Perform SCIM Create
  const createRes = http.post(`${BASE_URL}/api/v1/scim/Users`, payload, { headers });
  
  const createCheck = check(createRes, {
    'create status is 201': (r) => r.status === 201,
  });

  if (!createCheck) {
    errorRate.add(1);
  } else {
    userCreatedCount.add(1);
    
    // 3. Immediately attempt to fetch the newly created user
    const user = createRes.json();
    const fetchRes = http.get(`${BASE_URL}/api/v1/scim/Users/${user.id}`, { headers });
    
    check(fetchRes, {
      'fetch status is 200': (r) => r.status === 200,
    });
  }

  // Realistic delay between sync operations
  sleep(0.5);
}
