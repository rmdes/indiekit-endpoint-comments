import { test } from "node:test";
import assert from "node:assert/strict";
import { metadataToEndpoints, issuerMatches } from "../lib/auth/indieauth.js";

// IndieAuth server metadata. The document is preferred over rel=
// authorization_endpoint when present, and it is the only thing that carries an
// `issuer` — which the spec requires be compared to the `iss` returned on the
// authorization response using SIMPLE STRING COMPARISON, not URL normalisation.

const valid = {
  issuer: "https://a.example/",
  authorization_endpoint: "https://a.example/auth",
  token_endpoint: "https://a.example/auth/token",
  code_challenge_methods_supported: ["S256"],
};

test("reads endpoints and issuer from a valid document", () => {
  assert.deepEqual(metadataToEndpoints(valid), {
    issuer: "https://a.example/",
    authorizationEndpoint: "https://a.example/auth",
    tokenEndpoint: "https://a.example/auth/token",
  });
});

test("rejects a document missing any required field", () => {
  for (const key of Object.keys(valid)) {
    const partial = { ...valid };
    delete partial[key];
    assert.equal(metadataToEndpoints(partial), undefined, `missing ${key} must be rejected`);
  }
});

test("rejects a server that cannot do S256, which is the only method we send", () => {
  assert.equal(
    metadataToEndpoints({ ...valid, code_challenge_methods_supported: ["plain"] }),
    undefined,
  );
});

test("rejects non-object input", () => {
  for (const bad of [null, undefined, "string", 42, []]) {
    assert.equal(metadataToEndpoints(bad), undefined);
  }
});

test("issuerMatches requires exact string equality", () => {
  assert.equal(issuerMatches("https://a.example/", "https://a.example/"), true);
  // Simple string comparison per spec: a trailing slash difference is a mismatch
  assert.equal(issuerMatches("https://a.example", "https://a.example/"), false);
  assert.equal(issuerMatches("https://evil.example/", "https://a.example/"), false);
});

test("issuerMatches fails closed on a missing iss", () => {
  assert.equal(issuerMatches(undefined, "https://a.example/"), false);
  assert.equal(issuerMatches("", "https://a.example/"), false);
});

test("issuerMatches is skipped only when no issuer is known", () => {
  // Legacy servers publish no metadata and send no iss; nothing to compare.
  assert.equal(issuerMatches(undefined, undefined), true);
});
