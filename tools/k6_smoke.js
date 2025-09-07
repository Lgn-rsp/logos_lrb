import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
  vus: 50,
  duration: '60s',
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<500', 'p(99)<1500'],
  },
};

export default function () {
  http.get('http://127.0.0.1:8080/healthz');
  http.get('http://127.0.0.1:8080/economy');
  http.get('http://127.0.0.1:8080/balance/A');
  sleep(0.05);
}
