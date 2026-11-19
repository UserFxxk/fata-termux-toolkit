/**
 * Reference Express.js Application Security Hardening Blueprint
 * Based on the Authorized Agricultural Ration Solver API Assessment (SOLVER-01..08)
 *
 * Implements:
 * 1. Domain-Separated Numeric Bounds (NRC Dry Matter 0.5-100%, Live Body Weight 1.0-2500 kg)
 * 2. Client Pre-Solver Guard (Mitigates SOLVER-03 browser main-thread freeze on BB <= 0)
 * 3. Ownership-Scoped Authorization Filter (Mitigates SOLVER-01 & SOLVER-04 / CWE-306)
 * 4. Strict CORS Origin Allowlist & HTTP Security Headers (Mitigates SOLVER-05, 07, 08)
 */

const ALLOWED_CATEGORIES = new Set(["Forage", "Concentrate", "Mineral", "Vitamin"]);
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * SOLVER-03 Mitigation: Client/Server Pre-Solver Physiological Boundary Guard
 */
function validateAndRunSolver(bodyWeightKg, feeds) {
  if (typeof bodyWeightKg !== "number" || !Number.isFinite(bodyWeightKg) || bodyWeightKg < 1.0 || bodyWeightKg > 2500) {
    throw new RangeError("Livestock body weight (BB) must be between 1.0 kg and 2,500 kg (NRC Reference Range).");
  }
  if (!Array.isArray(feeds) || feeds.length === 0) {
    throw new RangeError("At least one validated feed ingredient is required.");
  }
  const targetDryMatterKg = Number((bodyWeightKg * 0.03).toFixed(2));
  return {
    bodyWeightKg,
    targetDryMatterKg,
    status: "OPTIMAL",
  };
}

/**
 * SOLVER-02 Mitigation: Feed Ingredient Catalog Schema Validator (NRC Dry Matter: 0.5% - 100%)
 */
function validateFeedIngredient(payload) {
  const errors = [];
  if (!payload || typeof payload !== "object") {
    return { success: false, errors: ["Request body must be a JSON object"] };
  }
  const name = typeof payload.name === "string" ? payload.name.trim() : "";
  if (name.length < 2 || name.length > 80) {
    errors.push("name: String must contain between 2 and 80 characters");
  }
  if (!ALLOWED_CATEGORIES.has(payload.category)) {
    errors.push("category: Must be one of Forage, Concentrate, Mineral, Vitamin");
  }
  const dm = payload.dryMatterPct;
  if (typeof dm !== "number" || !Number.isFinite(dm) || dm < 0.5 || dm > 100) {
    errors.push("dryMatterPct: Number must be between 0.5 and 100 (NRC Dry Matter percentage)");
  }
  return errors.length === 0
    ? { success: true, data: { name, category: payload.category, dryMatterPct: dm } }
    : { success: false, errors };
}

/**
 * SOLVER-03 Server Mitigation: Ration Formulation Request Schema Validator
 */
function validateRationSolveRequest(payload) {
  const errors = [];
  if (!payload || typeof payload !== "object") {
    return { success: false, errors: ["Request body must be a JSON object"] };
  }
  const bw = payload.bodyWeightKg;
  if (typeof bw !== "number" || !Number.isFinite(bw) || bw < 1.0 || bw > 2500) {
    errors.push("bodyWeightKg: Number must be between 1.0 and 2500 kg");
  }
  if (!Array.isArray(payload.feedIds) || payload.feedIds.length < 1 || payload.feedIds.length > 30) {
    errors.push("feedIds: Must be an array of 1 to 30 feed UUIDs");
  } else if (!payload.feedIds.every((id) => typeof id === "string" && UUID_REGEX.test(id))) {
    errors.push("feedIds: All elements must be valid UUIDs");
  }
  return errors.length === 0
    ? { success: true, data: { bodyWeightKg: bw, feedIds: payload.feedIds } }
    : { success: false, errors };
}

/**
 * SOLVER-01 & SOLVER-04 Mitigation: Authentication & Tenant Ownership Filter
 */
function getScopedHistory(records, authContext) {
  if (!authContext || !authContext.userId) {
    const err = new Error("Authentication required");
    err.statusCode = 401;
    throw err;
  }
  return records.filter((r) => r.userId === authContext.userId);
}

/**
 * SOLVER-05, SOLVER-07, SOLVER-08 Mitigation: Security Headers & CORS Origin Policy Builder
 */
function buildSecurityHeaders(requestOrigin, allowedOrigins = ["https://app.authorized-domain.example"]) {
  const headers = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "vary": "Origin",
  };
  if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
    headers["access-control-allow-origin"] = requestOrigin;
  }
  return headers;
}

module.exports = {
  validateAndRunSolver,
  validateFeedIngredient,
  validateRationSolveRequest,
  getScopedHistory,
  buildSecurityHeaders,
};
