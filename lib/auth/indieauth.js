/**
 * IndieAuth + RelMeAuth authentication for comments
 * @module auth/indieauth
 */

import { createHash, randomBytes } from "node:crypto";

import { mf2 } from "microformats-parser";

const INDIEAUTH_FALLBACK = "https://indieauth.com/auth";
const INDIEAUTH_TOKEN_FALLBACK = "https://tokens.indieauth.com/token";

/**
 * Read rel values out of an HTTP Link header
 *
 * Link headers are a header grammar, not markup, so a pattern is the right tool
 * here — unlike the document body, which mf2 parses properly.
 * @param {string} [value] - Raw Link header
 * @param {string} baseUrl - URL to resolve targets against
 * @returns {Record<string, string[]>} rel name to absolute URLs
 */
function relsFromLinkHeader(value, baseUrl) {
  const rels = {};
  if (!value) return rels;

  for (const [, target, params] of value.matchAll(/<([^>]+)>\s*;\s*([^,]*)/g)) {
    const rel = params.match(/rel\s*=\s*"?([^";]+)"?/i);
    if (!rel) continue;
    for (const name of rel[1].trim().split(/\s+/)) {
      try {
        (rels[name] ||= []).push(new URL(target.trim(), baseUrl).href);
      } catch {
        // Unresolvable target, ignore it
      }
    }
  }
  return rels;
}

/**
 * Find IndieAuth endpoints declared by a page
 *
 * Endpoints come from mf2's parsed rels rather than pattern matching, which
 * matters for correctness rather than tidiness: rels cover `<link>` and `<a>`,
 * either quoting style, multi-valued rels such as `rel="me
 * authorization_endpoint"`, and resolve relative URLs against the page. A rel
 * this misses does not fail loudly — it silently routes a visitor who runs
 * their own authorization server to the third-party fallback instead.
 *
 * HTTP Link headers take precedence over the document, per the specification.
 * @param {string} html - Page HTML
 * @param {string} url - Page URL, used as the resolution base
 * @param {string} [linkHeader] - Raw HTTP Link header, if any
 * @returns {{authorizationEndpoint?: string, tokenEndpoint?: string, metadataEndpoint?: string}}
 */
export function endpointsFromHtml(html, url, linkHeader) {
  const header = relsFromLinkHeader(linkHeader, url);

  let rels = {};
  try {
    rels = mf2(html, { baseUrl: url }).rels;
  } catch {
    // mf2 throws on empty or unparseable documents; headers may still carry it
  }

  const pick = (rel) => header[rel]?.[0] || rels[rel]?.[0];

  return {
    authorizationEndpoint: pick("authorization_endpoint"),
    tokenEndpoint: pick("token_endpoint"),
    metadataEndpoint: pick("indieauth-metadata"),
  };
}

/**
 * Discover a visitor's IndieAuth endpoints, falling back to indieauth.com
 *
 * indieauth.com accepts clients that are not pre-registered, which is why it
 * remains the fallback for visitors whose site declares no endpoint of its own.
 * @param {string} url - The visitor's website URL
 * @returns {Promise<{authorizationEndpoint: string, tokenEndpoint: string}>}
 */
export async function discoverEndpoints(url) {
  const response = await fetch(url, {
    headers: { Accept: "text/html" },
    redirect: "follow",
  });

  const html = await response.text();
  // Resolve against the final URL so redirects do not break relative rels
  const found = endpointsFromHtml(
    html,
    response.url || url,
    response.headers.get("link"),
  );

  return {
    authorizationEndpoint: found.authorizationEndpoint || INDIEAUTH_FALLBACK,
    tokenEndpoint: found.tokenEndpoint || INDIEAUTH_TOKEN_FALLBACK,
  };
}

/**
 * Compare two URLs for identity, ignoring a trailing slash
 * @param {string} a
 * @param {string} b
 * @returns {boolean} True when both name the same resource
 */
function sameUrl(a, b) {
  try {
    const x = new URL(a);
    const y = new URL(b);
    return (
      x.protocol === y.protocol &&
      x.host === y.host &&
      x.pathname.replace(/\/+$/, "") === y.pathname.replace(/\/+$/, "") &&
      x.search === y.search
    );
  } catch {
    return false;
  }
}

/**
 * Verify the authorization server may speak for the profile URL it returned
 *
 * IndieAuth 5.4: when the returned `me` is not the URL the visitor entered, the
 * client MUST re-discover that URL and confirm it declares the same
 * authorization endpoint. Without this any authorization endpoint can return
 * any `me` and be believed, which is impersonation of an arbitrary identity.
 *
 * Discovery is injectable so the check can be exercised without network access.
 * @param {string} returnedMe - Profile URL from the token response
 * @param {string} enteredMe - URL the visitor typed
 * @param {string} usedEndpoint - Authorization endpoint the code came from
 * @param {Function} [discover] - Endpoint discovery, defaults to the real one
 * @returns {Promise<boolean>} True when the claim is legitimate
 */
export async function verifyProfileUrl(
  returnedMe,
  enteredMe,
  usedEndpoint,
  discover = discoverEndpoints,
) {
  if (sameUrl(returnedMe, enteredMe)) return true;

  try {
    const { authorizationEndpoint } = await discover(returnedMe);
    return sameUrl(authorizationEndpoint, usedEndpoint);
  } catch {
    // Cannot confirm the claim, so do not accept it
    return false;
  }
}

/**
 * Generate PKCE code verifier and challenge
 * @returns {{verifier: string, challenge: string}}
 */
export function generatePKCE() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

/**
 * Generate a random state parameter
 * @returns {string}
 */
export function generateState() {
  return randomBytes(16).toString("base64url");
}

/**
 * Build the authorization URL
 * @param {object} params
 * @param {string} params.authorizationEndpoint
 * @param {string} params.clientId - The site URL (e.g. https://rmendes.net)
 * @param {string} params.redirectUri - Callback URL
 * @param {string} params.state
 * @param {string} params.codeChallenge
 * @param {string} params.me - The user's URL
 * @returns {string} Full authorization URL
 */
export function buildAuthUrl({
  authorizationEndpoint,
  clientId,
  redirectUri,
  state,
  codeChallenge,
  me,
}) {
  const url = new URL(authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("me", me);
  return url.toString();
}

/**
 * Exchange authorization code for token/profile
 * @param {object} params
 * @param {string} params.authorizationEndpoint - The auth endpoint to POST to
 * @param {string} params.code
 * @param {string} params.clientId
 * @param {string} params.redirectUri
 * @param {string} params.codeVerifier
 * @returns {Promise<{me: string}>} Authenticated profile URL
 */
export async function exchangeCode({
  authorizationEndpoint,
  code,
  clientId,
  redirectUri,
  codeVerifier,
}) {
  const response = await fetch(authorizationEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Token exchange failed: ${response.status} ${text}`);
  }

  const data = await response.json();
  if (!data.me) {
    throw new Error("No 'me' URL in token response");
  }

  return data;
}

/**
 * Pick the h-card that represents the page itself
 *
 * A page may carry several h-cards (comment authors, sidebar contacts). The one
 * that represents the page is the one claiming the page's own URL, so prefer a
 * card whose u-url or u-uid matches before falling back to the first card.
 * @param {Array<object>} items - Parsed microformat roots
 * @param {string} url - The page URL
 * @returns {object|undefined} Representative card, if any
 */
function representativeCard(items, url) {
  const cards = items.filter((item) => item.type?.includes("h-card"));
  const claimsUrl = (card) =>
    [...(card.properties.url || []), ...(card.properties.uid || [])].some(
      (value) => typeof value === "string" && value.replace(/\/+$/, "") === url.replace(/\/+$/, ""),
    );
  return cards.find(claimsUrl) || cards[0];
}

/**
 * Read the first usable URL from a microformat property
 *
 * u-photo is a plain string, or an object with `alt` and `value` when the
 * source element carried alt text.
 * @param {Array} [values] - Microformat property values
 * @returns {string} First URL, or an empty string
 */
function firstUrl(values) {
  const value = values?.[0];
  if (typeof value === "string") return value;
  return typeof value?.value === "string" ? value.value : "";
}

/**
 * Extract a display profile from a page's HTML
 *
 * Parsing is separated from fetching so it can be exercised directly. URLs come
 * back absolute: mf2 resolves them against `baseUrl`.
 * @param {string} html - Page HTML
 * @param {string} url - The page URL, used as the parser base
 * @returns {{name: string, photo: string, url: string}} Profile
 */
export function profileFromHtml(html, url) {
  const profile = { url, name: "", photo: "" };

  let parsed;
  try {
    parsed = mf2(html, { baseUrl: url });
  } catch {
    // mf2 throws on empty or unparseable documents
    return profile;
  }

  const card = representativeCard(parsed.items, url);
  if (card) {
    const name = card.properties.name?.[0];
    if (typeof name === "string") profile.name = name.trim();
    profile.photo = firstUrl(card.properties.photo);
  } else if (parsed.items.length === 0) {
    // Nothing marked up at all, so let metaformats synthesise a card from og:
    // tags. Gated on the page having NO microformats, because an h-entry on a
    // blog home page would otherwise hand back a post title as a person's name.
    // metaformats files og:image under `featured` and types the item h-entry
    // unless og:type is "profile".
    try {
      const [item] = mf2(html, {
        baseUrl: url,
        experimental: { metaformats: true },
      }).items;
      const name = item?.properties.name?.[0];
      if (typeof name === "string") profile.name = name.trim();
      if (item) profile.photo = firstUrl(item.properties.featured);
    } catch {
      // Leave the profile as-is
    }
  }

  // Site icons are a last resort, and rels are already absolute
  if (!profile.photo) {
    profile.photo =
      parsed.rels["apple-touch-icon"]?.[0] || parsed.rels.icon?.[0] || "";
  }

  return profile;
}

/**
 * Fetch a display profile from a URL
 *
 * Best-effort: a visitor authenticates regardless of what their page exposes.
 * @param {string} url - The visitor's website URL
 * @returns {Promise<{name: string, photo: string, url: string}>}
 */
export async function fetchProfile(url) {
  try {
    const response = await fetch(url, {
      headers: { Accept: "text/html" },
      redirect: "follow",
    });
    if (!response.ok) return { url, name: "", photo: "" };

    return profileFromHtml(await response.text(), url);
  } catch {
    return { url, name: "", photo: "" };
  }
}

/**
 * Hash an IP address for privacy-safe storage
 * @param {string} ip - Raw IP address
 * @returns {string} Hashed IP
 */
export function hashIP(ip) {
  return createHash("sha256").update(ip).digest("hex").substring(0, 16);
}
