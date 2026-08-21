import { test } from "node:test";
import assert from "node:assert/strict";
import { profileFromHtml } from "../lib/auth/indieauth.js";

// Display name and avatar come from the visitor's own page, so parsing has to
// survive whatever that page happens to be. These cover the shapes mf2 actually
// returns — verified against microformats-parser 2.0.6, not assumed.

const page = (body, head = "") =>
  `<!doctype html><html><head>${head}</head><body>${body}</body></html>`;

test("reads name and photo from an h-card", () => {
  const html = page(
    `<div class="h-card"><img class="u-photo" src="/me.jpg" alt="pic"><span class="p-name">Jane Visitor</span></div>`,
  );
  const profile = profileFromHtml(html, "https://visitor.example/");
  assert.equal(profile.name, "Jane Visitor");
  // Relative URLs are resolved against the page URL
  assert.equal(profile.photo, "https://visitor.example/me.jpg");
  assert.equal(profile.url, "https://visitor.example/");
});

test("u-photo without alt text is a bare string, not an object", () => {
  const html = page(
    `<div class="h-card"><img class="u-photo" src="/me.jpg"><span class="p-name">Jane</span></div>`,
  );
  assert.equal(
    profileFromHtml(html, "https://visitor.example/").photo,
    "https://visitor.example/me.jpg",
  );
});

test("prefers the h-card claiming the page's own URL", () => {
  const html = page(
    `<div class="h-card"><span class="p-name">Some Commenter</span></div>
     <div class="h-card"><a class="u-url" href="https://visitor.example/"></a><span class="p-name">Jane Visitor</span></div>`,
  );
  assert.equal(
    profileFromHtml(html, "https://visitor.example/").name,
    "Jane Visitor",
  );
});

test("falls back to og: tags when the page has no microformats", () => {
  const html = page(
    `<p>hello</p>`,
    `<meta property="og:title" content="Jane"><meta property="og:image" content="https://cdn.example/og.jpg">`,
  );
  const profile = profileFromHtml(html, "https://visitor.example/");
  assert.equal(profile.name, "Jane");
  // metaformats files og:image under `featured`, not `photo`
  assert.equal(profile.photo, "https://cdn.example/og.jpg");
});

test("falls back to site icons, preferring apple-touch-icon", () => {
  const html = page(
    `<p>hello</p>`,
    `<link rel="icon" href="/favicon.ico"><link rel="apple-touch-icon" href="/touch.png">`,
  );
  assert.equal(
    profileFromHtml(html, "https://visitor.example/").photo,
    "https://visitor.example/touch.png",
  );
});

test("returns an empty profile rather than throwing on unparseable HTML", () => {
  // mf2 throws on these; a visitor must still be able to sign in.
  for (const bad of ["", "just text", "<html><body></body></html>"]) {
    const profile = profileFromHtml(bad, "https://visitor.example/");
    assert.deepEqual(profile, {
      url: "https://visitor.example/",
      name: "",
      photo: "",
    });
  }
});

test("an h-card with no photo does not invent one from another card", () => {
  const html = page(
    `<div class="h-card"><a class="u-url" href="https://visitor.example/"></a><span class="p-name">Jane</span></div>`,
  );
  const profile = profileFromHtml(html, "https://visitor.example/");
  assert.equal(profile.name, "Jane");
  assert.equal(profile.photo, "");
});

test("a blog page's h-entry is never mistaken for the person's name", () => {
  // Regression guard: metaformats is gated on the page having NO microformats.
  // Without that gate, a real h-entry here would surface the post title as the
  // commenter's display name.
  const html = page(
    `<article class="h-entry"><h1 class="p-name">My Post About Cheese</h1></article>`,
    `<meta property="og:title" content="My Post About Cheese">`,
  );
  const profile = profileFromHtml(html, "https://visitor.example/");
  assert.equal(profile.name, "", "an h-entry must not supply a person's name");
});
