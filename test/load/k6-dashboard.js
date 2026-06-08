// k6 load test for the KubeGuard dashboard API (Squad P4).
// Run against a running dashboard:
//   BASE=http://localhost:8080 TOKEN=local-admin CLUSTER=prod-eu \
//     k6 run test/load/k6-dashboard.js
//
// Thresholds enforce the API p95 NFR (< 120ms) and a low error rate; k6 exits
// non-zero if they're breached, so this gates the CI/staging pipeline.
import http from "k6/http";
import { check, sleep } from "k6";

const BASE = __ENV.BASE || "http://localhost:8080";
const TOKEN = __ENV.TOKEN || "local-admin";
const CLUSTER = __ENV.CLUSTER || "prod-eu";
const headers = { Authorization: `Bearer ${TOKEN}` };

export const options = {
  scenarios: {
    reads: {
      executor: "ramping-vus",
      startVUs: 1,
      stages: [
        { duration: "30s", target: 50 },
        { duration: "1m", target: 50 },
        { duration: "30s", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_duration: ["p(95)<120"],
    http_req_failed: ["rate<0.01"],
  },
};

const endpoints = [
  `/v1/findings?cluster=${CLUSTER}&limit=20`,
  `/v1/posture?cluster=${CLUSTER}`,
  `/v1/attack-paths?cluster=${CLUSTER}`,
  `/v1/history?cluster=${CLUSTER}`,
  `/v1/clusters`,
];

export default function () {
  for (const path of endpoints) {
    const res = http.get(`${BASE}${path}`, { headers });
    check(res, { "status 200": (r) => r.status === 200 });
  }
  sleep(1);
}
