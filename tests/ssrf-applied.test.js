import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { discoverEndpoints, fetchProfile, exchangeCode, safeFetch } from "../lib/auth/indieauth.js";

// A guard nothing calls protects nothing. These start a REAL server on
// loopback that would answer if reached, so each test distinguishes "refused
// to fetch" from "fetched and failed" — 127.0.0.1 with nothing listening
// cannot tell those apart.

const withServer = async (handler, run) => {
  const server = http.createServer(handler);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}/`;
  try {
    return await run(url);
  } finally {
    server.close();
  }
};

test("discoverEndpoints refuses a loopback URL that would otherwise answer", async () => {
  let hits = 0;
  await withServer(
    (request, response) => {
      hits++;
      response.setHeader("content-type", "text/html");
      response.end(
        `<html><head><link rel="authorization_endpoint" href="https://attacker.example/auth"></head><body><p>x</p></body></html>`,
      );
    },
    async (url) => {
      const result = await discoverEndpoints(url);
      assert.equal(hits, 0, "the server must never be contacted");
      assert.equal(
        result.authorizationEndpoint,
        "https://indieauth.com/auth",
        "must fall back, not adopt the endpoint the blocked host served",
      );
    },
  );
});

test("fetchProfile refuses a loopback URL that would otherwise answer", async () => {
  let hits = 0;
  await withServer(
    (request, response) => {
      hits++;
      response.setHeader("content-type", "text/html");
      response.end(
        `<html><body><div class="h-card"><span class="p-name">Stolen Name</span></div></body></html>`,
      );
    },
    async (url) => {
      const profile = await fetchProfile(url);
      assert.equal(hits, 0, "the server must never be contacted");
      assert.equal(profile.name, "", "no profile data may come from a blocked host");
    },
  );
});

test("exchangeCode refuses to post the authorization code to a blocked host", async () => {
  // The authorization endpoint is discovered from the visitor's own page, so
  // it is attacker-chosen. Posting a code to loopback is an SSRF with a secret.
  let hits = 0;
  await withServer(
    (request, response) => {
      hits++;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ me: "https://rmendes.net/" }));
    },
    async (url) => {
      await assert.rejects(
        () =>
          exchangeCode({
            authorizationEndpoint: url,
            code: "abc",
            clientId: "https://rmendes.net",
            redirectUri: "https://rmendes.net/comments/auth/callback",
            codeVerifier: "v",
          }),
        /refus|blocked|not fetchable|Invalid/i,
      );
      assert.equal(hits, 0, "the code must never be sent to a blocked host");
    },
  );
});

test("the guard runs on every redirect hop, not only the first URL", async () => {
  // The bypass this closes: a permitted domain answers 302 to loopback.
  // Injected fetch, so this proves the hop logic rather than DNS behaviour.
  const seen = [];
  const fakeFetch = async (url) => {
    seen.push(url);
    if (url === "https://visitor.example/") {
      return new Response(null, {
        status: 302,
        headers: { location: "http://169.254.169.254/latest/meta-data/" },
      });
    }
    return new Response("<html><body><p>secrets</p></body></html>", { status: 200 });
  };

  await assert.rejects(
    () => safeFetch("https://visitor.example/", {}, fakeFetch),
    /blocked host/i,
  );
  assert.deepEqual(seen, ["https://visitor.example/"], "must stop before the metadata address");
});

test("safeFetch does not follow redirects for non-GET requests", async () => {
  // Replaying a POST body to a Location target would hand the authorization
  // code to whoever set the header.
  const seen = [];
  const fakeFetch = async (url) => {
    seen.push(url);
    return new Response(null, {
      status: 302,
      headers: { location: "https://elsewhere.example/" },
    });
  };

  const { response } = await safeFetch("https://visitor.example/", { method: "POST" }, fakeFetch);
  assert.equal(response.status, 302, "the redirect is returned, not followed");
  assert.deepEqual(seen, ["https://visitor.example/"]);
});

test("safeFetch gives up rather than following a redirect loop", async () => {
  let calls = 0;
  const fakeFetch = async () => {
    calls++;
    return new Response(null, {
      status: 302,
      headers: { location: "https://visitor.example/loop" },
    });
  };
  await assert.rejects(
    () => safeFetch("https://visitor.example/", {}, fakeFetch),
    /too many redirects/i,
  );
  assert.ok(calls <= 8, `bounded, got ${calls}`);
});
