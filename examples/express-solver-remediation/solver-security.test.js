const test = require("node:test");
const assert = require("node:assert/strict");
const {
  validateAndRunSolver,
  validateFeedIngredient,
  validateRationSolveRequest,
  getScopedHistory,
  buildSecurityHeaders,
} = require("./app");

const SAMPLE_RECORDS = [
  { id: "rec-1", userId: "user-001", animal: "Sapi Potong", resultKg: 12.5 },
  { id: "rec-2", userId: "user-002", animal: "Sapi Perah", resultKg: 14.0 },
];

test("SOLVER-01 & SOLVER-04 (CWE-306): rejects unauthenticated access (401) and scopes history to authenticated tenant", () => {
  assert.throws(
    () => getScopedHistory(SAMPLE_RECORDS, null),
    (err) => err.statusCode === 401 && /Authentication required/.test(err.message)
  );
  const scoped = getScopedHistory(SAMPLE_RECORDS, { userId: "user-001" });
  assert.equal(scoped.length, 1);
  assert.equal(scoped[0].userId, "user-001");
});

test("SOLVER-02 (CWE-20): rejects negative Dry Matter (-500%) and accepts valid NRC range (0.5% - 100%)", () => {
  const invalid = validateFeedIngredient({
    name: "VerificationFeed",
    category: "Mineral",
    dryMatterPct: -500,
  });
  assert.equal(invalid.success, false);
  assert.ok(invalid.errors.some((e) => e.includes("dryMatterPct")));

  const valid = validateFeedIngredient({
    name: "Napier Grass Forage",
    category: "Forage",
    dryMatterPct: 22.5,
  });
  assert.equal(valid.success, true);
});

test("SOLVER-03 (CWE-400): blocks non-positive bodyWeightKg (BB <= 0) in both client guard and server schema", () => {
  assert.throws(() => validateAndRunSolver(0, [{ name: "Grass" }]), RangeError);
  assert.throws(() => validateAndRunSolver(-50, [{ name: "Grass" }]), RangeError);

  const serverCheck = validateRationSolveRequest({
    bodyWeightKg: 0,
    feedIds: ["550e8400-e29b-41d4-a716-446655440000"],
  });
  assert.equal(serverCheck.success, false);
});

test("SOLVER-05, SOLVER-07 & SOLVER-08: enforces strict CORS allowlist, sets CSP/HSTS/XFO, and omits X-Powered-By", () => {
  const untrustedHeaders = buildSecurityHeaders("https://evil.example");
  assert.equal(untrustedHeaders["access-control-allow-origin"], undefined);
  assert.equal(untrustedHeaders["x-powered-by"], undefined);
  assert.equal(untrustedHeaders["content-security-policy"], "default-src 'self'");
  assert.equal(untrustedHeaders["x-frame-options"], "DENY");

  const trustedHeaders = buildSecurityHeaders("https://app.authorized-domain.example");
  assert.equal(trustedHeaders["access-control-allow-origin"], "https://app.authorized-domain.example");
});
