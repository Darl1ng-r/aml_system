import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.AML_BASE_URL || 'http://localhost:8000';
const AUTH_USERNAME = __ENV.AML_LOAD_USER || 'admin';
const AUTH_PASSWORD = __ENV.AML_LOAD_PASSWORD || 'admin123';
const PROFILE = (__ENV.AML_LOAD_PROFILE || '3x_spike').toLowerCase();

// Custom SLO metrics separating P0 critical compliance paths from sheddable P3 analytics
const p0Unexpected5xx = new Rate('p0_unexpected_5xx');
const p3GracefulShed = new Rate('p3_graceful_load_shed');
const p0IngestLatency = new Trend('p0_ingest_duration_ms');

const PROFILE_STAGES = {
  baseline: [
    { duration: '20s', target: 25 },
    { duration: '40s', target: 50 },
    { duration: '15s', target: 0 },
  ],
  soak: [
    { duration: '1m', target: 100 },
    { duration: '10m', target: 100 },
    { duration: '1m', target: 0 },
  ],
  '3x_spike': [
    { duration: '20s', target: 50 },   // Steady baseline
    { duration: '15s', target: 150 },  // 3x traffic spike
    { duration: '30s', target: 150 },  // Hold 3x peak (exercises HPA/KEDA + load shedding)
    { duration: '20s', target: 50 },   // Recovery verification (zero lingering 5xx)
    { duration: '15s', target: 0 },    // Cooldown
  ],
};

export const options = {
  stages: PROFILE_STAGES[PROFILE] || PROFILE_STAGES['3x_spike'],
  thresholds: {
    http_req_duration: ['p(95)<300', 'p(99)<750'],
    p0_ingest_duration_ms: ['p(95)<300', 'p(99)<750'],
    p0_unexpected_5xx: ['rate==0'],
    http_req_failed: ['rate<0.02'],
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
  const roll = deterministicRandom();
  const baseHeaders = {
    'Content-Type': 'application/json',
    'X-CSRF-Protection': '1',
    Authorization: `Bearer ${data.token}`,
  };

  if (roll < 0.55) {
    // P0_CRITICAL: High-throughput transaction ingestion with unique Idempotency-Key
    const senderIdx = Math.floor(deterministicRandom() * accounts.length);
    const receiverIdx = (senderIdx + 1) % accounts.length;
    const idemKey = `k6-${__VU}-${__ITER}-${Date.now()}`;

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

    const res = http.post(`${BASE_URL}/api/v1/transactions/ingest`, payload, {
      headers: { ...baseHeaders, 'Idempotency-Key': idemKey },
      tags: { priority_tier: 'P0_CRITICAL' },
    });
    p0IngestLatency.add(res.timings.duration);
    p0Unexpected5xx.add(res.status >= 500);
    check(res, {
      'P0 ingest accepted (200/201/202)': (r) =>
        r.status === 200 || r.status === 201 || r.status === 202,
    });
  } else if (roll < 0.80) {
    // P1_HIGH: Keyset-paginated alert triage read (hits Read Replicas)
    const res = http.get(`${BASE_URL}/api/v1/alerts?limit=25`, {
      headers: baseHeaders,
      tags: { priority_tier: 'P1_HIGH' },
    });
    p0Unexpected5xx.add(res.status >= 500);
    check(res, { 'P1 alerts read 200': (r) => r.status === 200 });
  } else if (roll < 0.92) {
    // P3_SHEDDABLE: Cached compliance report (graceful 503 + Retry-After allowed under 3x spike)
    const res = http.get(`${BASE_URL}/api/v1/reports/sar-summary`, {
      headers: baseHeaders,
      tags: { priority_tier: 'P3_SHEDDABLE' },
    });
    const isGracefulShed = res.status === 503 && Boolean(res.headers['Retry-After']);
    p3GracefulShed.add(isGracefulShed);
    check(res, {
      'P3 report 200 or graceful 503 load-shed': (r) =>
        r.status === 200 || (r.status === 503 && Boolean(r.headers['Retry-After'])),
    });
  } else if (roll < 0.97) {
    // P3_SHEDDABLE: Async export queue offload (202 Accepted or graceful 503 shed)
    const res = http.get(`${BASE_URL}/api/v1/alerts/export/pdf?async_mode=true`, {
      headers: { ...baseHeaders, 'Idempotency-Key': `k6-exp-${__VU}-${__ITER}` },
      tags: { priority_tier: 'P3_SHEDDABLE' },
    });
    const isGracefulShed = res.status === 503 && Boolean(res.headers['Retry-After']);
    p3GracefulShed.add(isGracefulShed);
    check(res, {
      'P3 async export 202 or graceful 503 load-shed': (r) =>
        r.status === 202 || (r.status === 503 && Boolean(r.headers['Retry-After'])),
    });
  } else {
    // P0_CRITICAL: Rolling-deploy readiness verification
    const res = http.get(`${BASE_URL}/health/ready`, {
      tags: { priority_tier: 'P0_CRITICAL' },
    });
    check(res, { 'readiness 200': (r) => r.status === 200 });
  }

  sleep(0.1);
}
