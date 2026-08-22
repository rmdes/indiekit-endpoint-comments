import { test } from "node:test";
import assert from "node:assert/strict";
import { isFetchableUrl } from "../lib/auth/indieauth.js";

// The sign-in form decides where this server sends requests: a visitor submits
// a URL and we fetch it, then fetch what it points at. Unrestricted, that is
// blind SSRF against loopback, private ranges and cloud metadata. Ported from
// harden-client-discovery.patch (endpoint-auth, 2026-08-16) rather than
// re-derived, so both behave identically.

test("accepts ordinary web URLs", () => {
  assert.equal(isFetchableUrl("https://visitor.example/"), true);
  assert.equal(isFetchableUrl("https://sub.visitor.example/path"), true);
  // The spec permits http as well as https for profile URLs
  assert.equal(isFetchableUrl("http://visitor.example/"), true);
});

test("rejects schemes that are not http or https", () => {
  for (const url of [
    "file:///etc/passwd",
    "ftp://visitor.example/",
    "gopher://visitor.example/",
    "data:text/html,hi",
  ]) {
    assert.equal(isFetchableUrl(url), false, url);
  }
});

test("rejects localhost by name", () => {
  for (const url of [
    "http://localhost/",
    "http://localhost:8080/",
    "http://LOCALHOST/",
    "http://anything.localhost/",
  ]) {
    assert.equal(isFetchableUrl(url), false, url);
  }
});

test("rejects every IPv4 literal, not merely private ranges", () => {
  // No IP literal is a valid profile URL, so none is worth fetching.
  for (const url of [
    "http://127.0.0.1/",
    "http://169.254.169.254/",   // cloud metadata
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://8.8.8.8/",           // public, still refused
  ]) {
    assert.equal(isFetchableUrl(url), false, url);
  }
});

test("rejects IPv6 literals including the bracketed form", () => {
  for (const url of ["http://[::1]/", "http://[fd00::1]/", "http://[::ffff:127.0.0.1]/"]) {
    assert.equal(isFetchableUrl(url), false, url);
  }
});

test("rejects numeric host encodings the resolver accepts but net.isIP does not", () => {
  // All three resolve to 127.0.0.1 and would otherwise pass as domain names.
  for (const url of [
    "http://2130706433/",     // decimal
    "http://0x7f000001/",     // hexadecimal
    "http://0177.0.0.1/",     // octal
  ]) {
    assert.equal(isFetchableUrl(url), false, url);
  }
});

test("rejects input that is not a URL at all", () => {
  for (const bad of ["", "not a url", "://nope", undefined, null]) {
    assert.equal(isFetchableUrl(bad), false, String(bad));
  }
});
