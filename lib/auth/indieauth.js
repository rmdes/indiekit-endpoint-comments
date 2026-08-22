/**
 * IndieAuth + RelMeAuth authentication for comments
 * @module auth/indieauth
 */

import { createHash, randomBytes } from "node:crypto";
import net from "node:net";

import { mf2 } from "microformats-parser";

const INDIEAUTH_FALLBACK = "https://indieauth.com/auth";
const INDIEAUTH_TOKEN_FALLBACK = "https://tokens.indieauth.com/token";

/** Outbound fetches give up after this long. */
const FETCH_TIMEOUT = 5000;

/**
 * Check whether a visitor-supplied URL may be fetched
 *
 * The sign-in form decides where this server sends requests: a visitor submits
 * a URL, we fetch it, and then fetch what it points at. Unrestricted that is
 * blind SSRF — loopback services, private ranges, and the cloud metadata
 * address at 169.254.169.254.
 *
 * A profile URL's host must be a domain name, so no IP literal is worth
 * fetching and refusing all of them is simpler and closer to the specification
 * than sorting internal ranges from public ones.
 *
 * Ported from harden-client-discovery.patch (endpoint-auth, 2026-08-16) so both
 * behave identically; fix bugs in both.
 *
 * A domain name is trusted without resolving it, so one pointing at an internal
 * address still passes. Closing that means resolving first and connecting to
 * the address that was checked, which needs a custom dispatcher.
 * @param {string} url - Candidate URL
 * @returns {boolean} True when the URL is safe to fetch
 * @see {@link https://indieauth.spec.indieweb.org/#client-identifier}
 */
export function isFetchableUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return false;
  }

  const hostname = parsed.hostname.replaceAll(/^\[|]$/g, "").toLowerCase();

  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
    return false;
  }

  // Any IP literal, loopback or not: none are valid profile URLs
  if (net.isIP(hostname) !== 0) {
    return false;
  }

  // Decimal, hexadecimal and octal encodings of an address (`2130706433`,
  // `0x7f000001`, `0177.0.0.1`) are resolved by the system resolver but are not
  // recognised by net.isIP, so they would otherwise pass as domain names
  if (
    /^\d+$/.test(hostname) ||
    /^0x[\da-f]+$/.test(hostname) ||
    /^[\d.]+$/.test(hostname)
  ) {
    return false;
  }

  return true;
}

/** Redirect hops followed before giving up. */
const MAX_REDIRECTS = 5;

/**
 * Fetch a visitor-supplied URL, refusing hosts that must not be reached
 *
 * Redirects are followed by hand because `isFetchableUrl` has to run on every
 * hop: a permitted domain answering 302 to 169.254.169.254 would otherwise walk
 * straight through a guard applied only to the URL we started with.
 *
 * Redirects are never followed for non-GET requests. `exchangeCode` posts an
 * authorization code, and replaying that to whatever a Location header names
 * would hand the code to a third party.
 * `doFetch` is injectable so the hop logic can be exercised without network.
 * @param {string} url - URL to fetch
 * @param {object} [options] - fetch options
 * @param {Function} [doFetch] - fetch implementation, defaults to global fetch
 * @returns {Promise<{response: Response, finalUrl: string}>}
 * @throws {Error} When the URL, or any hop, must not be fetched
 */
export async function safeFetch(url, options = {}, doFetch = fetch) {
  const method = options.method || "GET";
  let current = url;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!isFetchableUrl(current)) {
      throw new Error(`Refusing to fetch blocked host: ${current}`);
    }

    const response = await doFetch(current, {
      ...options,
      redirect: "manual",
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });

    const location = response.headers.get("location");
    const redirected = response.status >= 300 && response.status < 400;

    if (!redirected || !location || method !== "GET") {
      return { response, finalUrl: current };
    }

    current = new URL(location, current).href;
  }

  throw new Error("Too many redirects");
}

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
 * Read endpoints out of an IndieAuth server metadata document
 *
 * `issuer`, `authorization_endpoint`, `token_endpoint` and
 * `code_challenge_methods_supported` are all required — the last one is not
 * optional as it is in RFC 8414, because PKCE is mandatory in IndieAuth. A
 * document missing any of them, or unable to do S256, is unusable rather than
 * partially usable, so it is refused and discovery falls back to the rels.
 * @param {object} metadata - Parsed metadata document
 * @returns {{issuer: string, authorizationEndpoint: string, tokenEndpoint: string}|undefined}
 */
export function metadataToEndpoints(metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return undefined;
  }

  const { issuer, authorization_endpoint, token_endpoint } = metadata;
  const methods = metadata.code_challenge_methods_supported;

  if (
    typeof issuer !== "string" ||
    typeof authorization_endpoint !== "string" ||
    typeof token_endpoint !== "string" ||
    !Array.isArray(methods) ||
    !methods.includes("S256")
  ) {
    return undefined;
  }

  return {
    issuer,
    authorizationEndpoint: authorization_endpoint,
    tokenEndpoint: token_endpoint,
  };
}

/**
 * Compare the `iss` on an authorization response to the metadata issuer
 *
 * The specification requires simple string comparison here, so this deliberately
 * does NOT normalise URLs: a trailing-slash difference is a mismatch. When no
 * issuer is known the server published no metadata and sends no `iss`, so there
 * is nothing to compare and the check does not apply.
 * @param {string} [iss] - `iss` from the authorization response
 * @param {string} [issuer] - Issuer recorded at discovery, if any
 * @returns {boolean} True when the response may be trusted
 */
export function issuerMatches(iss, issuer) {
  if (!issuer) return true;
  return Boolean(iss) && iss === issuer;
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
  let response;
  let finalUrl;
  try {
    ({ response, finalUrl } = await safeFetch(url, {
      headers: { Accept: "text/html" },
    }));
  } catch {
    // Blocked, unreachable or timed out: fall back rather than fail the login
    return {
      authorizationEndpoint: INDIEAUTH_FALLBACK,
      tokenEndpoint: INDIEAUTH_TOKEN_FALLBACK,
    };
  }

  const html = await response.text();
  // Resolve against the final URL so redirects do not break relative rels
  const found = endpointsFromHtml(html, finalUrl, response.headers.get("link"));

  // Metadata is preferred over the rels when advertised; the rels remain the
  // compatibility path for servers predating the metadata document.
  if (found.metadataEndpoint) {
    const metadata = await fetchMetadata(found.metadataEndpoint);
    if (metadata) return metadata;
  }

  return {
    authorizationEndpoint: found.authorizationEndpoint || INDIEAUTH_FALLBACK,
    tokenEndpoint: found.tokenEndpoint || INDIEAUTH_TOKEN_FALLBACK,
  };
}

/**
 * Fetch and validate a metadata document
 * @param {string} url - Metadata endpoint
 * @returns {Promise<object|undefined>} Endpoints, or undefined if unusable
 */
async function fetchMetadata(url) {
  try {
    // The metadata URL comes from the visitor's own page, so it is chosen by
    // whoever controls that page
    const { response } = await safeFetch(url, {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) return undefined;
    return metadataToEndpoints(await response.json());
  } catch {
    // Unreachable or malformed, fall back to the rels
    return undefined;
  }
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
  // The authorization endpoint was discovered from the visitor's own page, so
  // posting a code to it is a request to an attacker-chosen URL
  const { response } = await safeFetch(authorizationEndpoint, {
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
    const { response, finalUrl } = await safeFetch(url, {
      headers: { Accept: "text/html" },
    });
    if (!response.ok) return { url, name: "", photo: "" };

    return { ...profileFromHtml(await response.text(), finalUrl), url };
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
