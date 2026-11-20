import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.AML_BASE_URL || 'http://localhost:8000';
const AUTH_USERNAME = __ENV.AML_LOAD_USER || 'admin';
const AUTH_PASSWORD = __ENV.AML_LOAD_PASSWORD || 'admin123';

export const options = {
  stages: [
    { duration: '15s', target: 20 },  // Ramp up to 20 users
    { duration: '30s', target: 50 },  // Spike to 50 users
    { duration: '15s', target: 0 },   // Cool down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests must finish within 500ms (SLO)
    http_req_failed: ['rate<0.01'],   // Less than 1% errors
  },
};

const accounts = [
  'ACCT-0a2e9dcd',
  'ACCT-1b3f8eae',
  'ACCT-2c4a7fbf',
  'ACCT-3d5b6aca',
];

let seed = 42;
function deterministicRandom() {
  seed = (seed * 1664525 + 1013904223) % 4294967296;
  return seed / 4294967296;
}

export function setup() {
  const loginRes = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    { username: AUTH_USERNAME, password: AUTH_PASSWORD },
    { headers: { 'X-CSRF-Protection': '1' } }
  );
  check(loginRes, { 'authenticated load test session': (r) => r.status === 200 });
  const body = loginRes.json();
  return { token: body && body.access_token ? body.access_token : '' };
}

export default function runLoadTest(data) {
  const url = `${BASE_URL}/api/v1/transactions/ingest`;
  const senderIdx = Math.floor(deterministicRandom() * accounts.length);
  const receiverIdx = (senderIdx + 1) % accounts.length;

  const payload = JSON.stringify({
    sender_account: accounts[senderIdx],
    receiver_account: accounts[receiverIdx],
    amount: Number.parseFloat((deterministicRandom() * 12000 + 20).toFixed(2)),
    currency: 'USD',
    timestamp: new Date().toISOString(),
    country: 'US',
    merchant: 'Global Settlement Core',
    device: 'API-Gateway-Cluster',
    channel: 'Wire',
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Protection': '1',
      Authorization: `Bearer ${data.token}`,
    },
  };

  const res = http.post(url, payload, params);
  check(res, {
    'status is successful (200/201/202)': (r) =>
      r.status === 200 || r.status === 201 || r.status === 202,
  });

  sleep(0.1);
}
