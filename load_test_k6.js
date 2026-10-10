import http from 'k6/http';
import { check, sleep } from 'k6';

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
  "DE12003400567890111100",
  "US99887766554433221100",
  "GB44332211009988776655",
  "RU11223344556677889900"
];

export default function () {
  const url = 'http://localhost:8000/api/v1/transactions';
  const sender = accounts[Math.floor(Math.random() * accounts.length)];
  const receiver = accounts[Math.floor(Math.random() * accounts.length)];

  const payload = JSON.stringify({
    sender_account_id: sender,
    receiver_account_id: receiver,
    amount: parseFloat((Math.random() * 12000 + 20).toFixed(2)),
    currency: 'USD',
    country: 'US',
    merchant: 'Global Settlement Core',
    device: 'API-Gateway-Cluster',
    channel: 'Wire'
  });

  const params = {
    headers: { 'Content-Type': 'application/json' },
  };

  const res = http.post(url, payload, params);
  check(res, {
    'status is successful (200/201)': (r) => r.status === 200 || r.status === 201,
  });

  sleep(0.1);
}
