import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyProfileUrl } from "../lib/auth/indieauth.js";

// IndieAuth 5.4: when the profile URL returned by the authorization server is
// not the one the visitor entered, the client MUST re-discover the returned URL
// and confirm it declares the SAME authorization endpoint. Without this, any
// authorization endpoint can return any `me` and claim any identity — including
// the site owner's.

const discoverStub = (map) => async (url) => {
  if (!(url in map)) throw new Error(`unexpected discovery for ${url}`);
  if (map[url] === null) throw new Error("discovery failed");
  return { authorizationEndpoint: map[url] };
};

test("accepts the profile URL the visitor entered", async () => {
  let called = false;
  const ok = await verifyProfileUrl(
    "https://visitor.example/",
    "https://visitor.example/",
    "https://visitor.example/auth",
    async () => { called = true; return {}; },
  );
  assert.equal(ok, true);
  assert.equal(called, false, "no re-discovery needed when the URL is unchanged");
});

test("treats a trailing-slash difference as the same URL", async () => {
  const ok = await verifyProfileUrl(
    "https://visitor.example",
    "https://visitor.example/",
    "https://visitor.example/auth",
    async () => { throw new Error("must not re-discover"); },
  );
  assert.equal(ok, true);
});

test("accepts a different profile URL that declares the same endpoint", async () => {
  // Legitimate: entered rick.example, server canonicalised to www.rick.example,
  // and that URL genuinely delegates to the same authorization endpoint.
  const ok = await verifyProfileUrl(
    "https://www.rick.example/",
    "https://rick.example/",
    "https://auth.rick.example/",
    discoverStub({ "https://www.rick.example/": "https://auth.rick.example/" }),
  );
  assert.equal(ok, true);
});

test("REJECTS a profile URL that declares a different endpoint", async () => {
  // The attack: evil.example's own endpoint returns me=https://rmendes.net.
  // rmendes.net declares its own endpoint, so the claim is refused.
  const ok = await verifyProfileUrl(
    "https://rmendes.net/",
    "https://evil.example/",
    "https://evil.example/auth",
    discoverStub({ "https://rmendes.net/": "https://rmendes.net/auth" }),
  );
  assert.equal(ok, false);
});

test("fails closed when re-discovery cannot be completed", async () => {
  const ok = await verifyProfileUrl(
    "https://rmendes.net/",
    "https://evil.example/",
    "https://evil.example/auth",
    discoverStub({ "https://rmendes.net/": null }),
  );
  assert.equal(ok, false);
});
