import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  scenarios: {
    active: {
      executor: 'constant-vus',
      vus: 50,
      duration: '20s',
      gracefulStop: '5s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.001'],
    http_req_duration: ['p(95)<50'],
  },
  noConnectionReuse: false,
};

// absolute paths for k6 (it runs from the cwd passed)
const URLS = [
  '/ok.txt',
  '/index.html',
  '/payload_1k.bin',
  '/healthz',
  '/payload_16k.bin',
];

const BASE = 'http://127.0.0.1:18080';

export default function () {
  let url = BASE + URLS[Math.floor(Math.random() * URLS.length)];
  let res = http.get(url);
  check(res, { 'status 200': (r) => r.status === 200 });
}
