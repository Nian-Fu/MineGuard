import http from 'k6/http'
import { check, fail, sleep } from 'k6'

const baseUrl = (__ENV.MINEGUARD_BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')

export const options = {
  discardResponseBodies: true,
  scenarios: {
    console_reads: {
      executor: 'ramping-arrival-rate',
      startRate: 5,
      timeUnit: '1s',
      preAllocatedVUs: 20,
      maxVUs: 100,
      stages: [
        { target: 20, duration: '2m' },
        { target: 20, duration: '5m' },
        { target: 40, duration: '2m' },
        { target: 40, duration: '5m' },
        { target: 0, duration: '1m' },
      ],
    },
  },
  thresholds: {
    checks: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    dropped_iterations: ['count==0'],
  },
}

export function setup() {
  const username = __ENV.MINEGUARD_LOAD_USERNAME
  const password = __ENV.MINEGUARD_LOAD_PASSWORD
  if (!username || !password) {
    fail('MINEGUARD_LOAD_USERNAME and MINEGUARD_LOAD_PASSWORD are required')
  }
  const response = http.post(
    `${baseUrl}/api/v1/auth/login`,
    JSON.stringify({ username, password }),
    {
      headers: { 'Content-Type': 'application/json' },
      responseType: 'text',
      tags: { operation: 'login-setup' },
    },
  )
  const passed = check(response, {
    'load-test login succeeds': (item) => item.status === 200,
  })
  if (!passed) fail(`load-test login failed with HTTP ${response.status}`)
  const payload = response.json()
  if (!payload.access_token) fail('login response did not contain an access token')
  return { accessToken: payload.access_token }
}

export default function runConsoleReads(data) {
  const params = {
    headers: { Authorization: `Bearer ${data.accessToken}` },
  }
  const responses = http.batch([
    ['GET', `${baseUrl}/api/v1/dashboard/summary`, null, { ...params, tags: { operation: 'dashboard' } }],
    ['GET', `${baseUrl}/api/v1/cameras?page_size=100`, null, { ...params, tags: { operation: 'cameras' } }],
    ['GET', `${baseUrl}/api/v1/events?page_size=100`, null, { ...params, tags: { operation: 'events' } }],
    ['GET', `${baseUrl}/api/v1/notification-deliveries?page_size=100`, null, { ...params, tags: { operation: 'deliveries' } }],
  ])
  check(responses, {
    'all console reads succeed': (items) => items.every((item) => item.status === 200),
  })
  sleep(0.2 + Math.random() * 0.8)
}
