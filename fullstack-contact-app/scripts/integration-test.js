#!/usr/bin/env node
/**
 * Integration test against the LIVE deployed API. Not run in CI (would hit
 * real infra / the WAF rate limit on every push) — run it manually after a
 * deploy:
 *
 *   node scripts/integration-test.js https://your-api.execute-api.region.amazonaws.com/prod
 */
const BASE_URL = process.argv[2] || process.env.API_BASE_URL;

if (!BASE_URL) {
  console.error("Usage: node integration-test.js <api-base-url>");
  console.error("   or: API_BASE_URL=https://... node integration-test.js");
  process.exit(1);
}

let passed = 0;
let failed = 0;

function check(description, condition) {
  if (condition) {
    console.log(`  \x1b[32m✓\x1b[0m ${description}`);
    passed++;
  } else {
    console.log(`  \x1b[31m✗\x1b[0m ${description}`);
    failed++;
  }
}

async function testValidSubmission() {
  console.log("POST /contact — valid submission");
  const res = await fetch(`${BASE_URL}/contact`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Integration Test", email: "integration-test@example.com" }),
  });
  const body = await res.json();
  check("returns 200", res.status === 200);
  check("message mentions the submitted name", (body.message || "").includes("Integration Test"));
  check("CORS header present", res.headers.has("access-control-allow-origin"));
}

async function testMissingName() {
  console.log("POST /contact — missing name");
  const res = await fetch(`${BASE_URL}/contact`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "test@example.com" }),
  });
  const body = await res.json();
  check("returns 400", res.status === 400);
  check("error mentions name", /name/i.test(body.error || ""));
}

async function testInvalidEmail() {
  console.log("POST /contact — invalid email");
  const res = await fetch(`${BASE_URL}/contact`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Test", email: "not-an-email" }),
  });
  const body = await res.json();
  check("returns 400", res.status === 400);
  check("error mentions email", /email/i.test(body.error || ""));
}

async function testMalformedJson() {
  console.log("POST /contact — malformed JSON body");
  const res = await fetch(`${BASE_URL}/contact`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{not valid json",
  });
  check("returns 400", res.status === 400);
}

async function testRecentSubmissions() {
  console.log("GET /submissions");
  const res = await fetch(`${BASE_URL}/submissions`);
  const body = await res.json();
  check("returns 200", res.status === 200);
  check("returns a submissions array", Array.isArray(body.submissions));
  if (body.submissions.length > 0) {
    check("emails are masked (contain '*')", body.submissions.every((s) => s.email.includes("*")));
    check("raw submitted email is not exposed", !body.submissions.some((s) => s.email === "integration-test@example.com"));
  }
}

async function testCorsPreflight() {
  console.log("OPTIONS /contact — CORS preflight");
  const res = await fetch(`${BASE_URL}/contact`, { method: "OPTIONS" });
  check("returns 200", res.status === 200);
  check("Access-Control-Allow-Methods present", res.headers.has("access-control-allow-methods"));
}

(async () => {
  console.log(`Running integration tests against ${BASE_URL}\n`);
  await testValidSubmission();
  await testMissingName();
  await testInvalidEmail();
  await testMalformedJson();
  await testRecentSubmissions();
  await testCorsPreflight();

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
})();
