import { test } from "node:test";
import assert from "node:assert/strict";
import { endpointsFromHtml } from "../lib/auth/indieauth.js";

// Endpoint discovery decides which server may assert a visitor's identity, so a
// missed rel is not cosmetic: it silently routes someone who runs their own
// IndieAuth server to a third-party fallback instead. The regex this replaced
// handled only `<link rel="x" href="y">` with double quotes and an absolute URL.

const page = (head) => `<html><head>${head}</head><body><p>x</p></body></html>`;
const BASE = "https://visitor.example/";

test("reads a plain link element", () => {
  const r = endpointsFromHtml(page(`<link rel="authorization_endpoint" href="https://a.example/auth">`), BASE);
  assert.equal(r.authorizationEndpoint, "https://a.example/auth");
});

test("resolves a relative href against the page URL", () => {
  const r = endpointsFromHtml(page(`<link rel="authorization_endpoint" href="/auth">`), BASE);
  assert.equal(r.authorizationEndpoint, "https://visitor.example/auth");
});

test("accepts single-quoted attributes", () => {
  const r = endpointsFromHtml(page(`<link rel='authorization_endpoint' href='https://a.example/auth'>`), BASE);
  assert.equal(r.authorizationEndpoint, "https://a.example/auth");
});

test("accepts a rel with several space-separated values", () => {
  const r = endpointsFromHtml(page(`<link rel="me authorization_endpoint" href="https://a.example/auth">`), BASE);
  assert.equal(r.authorizationEndpoint, "https://a.example/auth");
});

test("accepts an anchor element, which the specification also permits", () => {
  const html = `<html><head></head><body><a rel="authorization_endpoint" href="https://a.example/auth">x</a></body></html>`;
  assert.equal(endpointsFromHtml(html, BASE).authorizationEndpoint, "https://a.example/auth");
});

test("reads the token endpoint too", () => {
  const r = endpointsFromHtml(page(`<link rel="token_endpoint" href="/auth/token">`), BASE);
  assert.equal(r.tokenEndpoint, "https://visitor.example/auth/token");
});

test("HTTP Link headers take precedence over the document", () => {
  const html = page(`<link rel="authorization_endpoint" href="https://from-html.example/auth">`);
  const header = '<https://from-header.example/auth>; rel="authorization_endpoint"';
  assert.equal(endpointsFromHtml(html, BASE, header).authorizationEndpoint, "https://from-header.example/auth");
});

test("parses a Link header carrying several values and rels", () => {
  const header = '<https://h.example/hub>; rel="hub", <https://h.example/auth>; rel="authorization_endpoint", <https://h.example/t>; rel="token_endpoint"';
  const r = endpointsFromHtml(page(""), BASE, header);
  assert.equal(r.authorizationEndpoint, "https://h.example/auth");
  assert.equal(r.tokenEndpoint, "https://h.example/t");
});

test("returns nothing discoverable rather than throwing on unparseable HTML", () => {
  const r = endpointsFromHtml("", BASE);
  assert.equal(r.authorizationEndpoint, undefined);
  assert.equal(r.tokenEndpoint, undefined);
});
