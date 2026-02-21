/**
 * IndieAuth + RelMeAuth authentication for comments
 * @module auth/indieauth
 */

import { createHash, randomBytes } from "node:crypto";

const INDIEAUTH_FALLBACK = "https://indieauth.com/auth";

/**
 * Discover authorization endpoint from a URL
 * @param {string} url - The user's website URL
 * @returns {Promise<{authorizationEndpoint: string, tokenEndpoint: string}>}
 */
export async function discoverEndpoints(url) {
  const response = await fetch(url, {
    headers: { Accept: "text/html" },
    redirect: "follow",
  });

  let authorizationEndpoint = null;
  let tokenEndpoint = null;

  // Check Link headers first
  const linkHeader = response.headers.get("link");
  if (linkHeader) {
    const authMatch = linkHeader.match(
      /<([^>]+)>;\s*rel="authorization_endpoint"/,
    );
    const tokenMatch = linkHeader.match(/<([^>]+)>;\s*rel="token_endpoint"/);
    if (authMatch) authorizationEndpoint = authMatch[1];
    if (tokenMatch) tokenEndpoint = tokenMatch[1];
  }

  // Fall back to HTML parsing
  if (!authorizationEndpoint || !tokenEndpoint) {
    const html = await response.text();
    if (!authorizationEndpoint) {
      const match = html.match(
        /<link[^>]+rel="authorization_endpoint"[^>]+href="([^"]+)"/,
      );
      if (!match) {
        const match2 = html.match(
          /<link[^>]+href="([^"]+)"[^>]+rel="authorization_endpoint"/,
        );
        if (match2) authorizationEndpoint = match2[1];
      } else {
        authorizationEndpoint = match[1];
      }
    }
    if (!tokenEndpoint) {
      const match = html.match(
        /<link[^>]+rel="token_endpoint"[^>]+href="([^"]+)"/,
      );
      if (!match) {
        const match2 = html.match(
          /<link[^>]+href="([^"]+)"[^>]+rel="token_endpoint"/,
        );
        if (match2) tokenEndpoint = match2[1];
      } else {
        tokenEndpoint = match[1];
      }
    }
  }

  return {
    authorizationEndpoint: authorizationEndpoint || INDIEAUTH_FALLBACK,
    tokenEndpoint: tokenEndpoint || "https://tokens.indieauth.com/token",
  };
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
 * Fetch h-card profile from a URL
 * @param {string} url - The user's website URL
 * @returns {Promise<{name: string, photo: string, url: string}>}
 */
export async function fetchProfile(url) {
  const profile = { url, name: "", photo: "" };

  try {
    const response = await fetch(url, {
      headers: { Accept: "text/html" },
      redirect: "follow",
    });
    if (!response.ok) return profile;

    const html = await response.text();

    // Extract name from h-card
    const nameMatch = html.match(
      /class="[^"]*p-name[^"]*"[^>]*>([^<]+)</,
    );
    if (nameMatch) profile.name = nameMatch[1].trim();

    // Extract photo from h-card
    const photoMatch = html.match(
      /class="[^"]*u-photo[^"]*"[^>]*src="([^"]+)"/,
    );
    if (photoMatch) profile.photo = photoMatch[1];

    // Fallback: try rel="me" photo or meta tags
    if (!profile.name) {
      const metaName = html.match(
        /<meta[^>]+name="author"[^>]+content="([^"]+)"/,
      );
      if (metaName) profile.name = metaName[1];
    }
  } catch {
    // Profile fetch is best-effort
  }

  return profile;
}

/**
 * Hash an IP address for privacy-safe storage
 * @param {string} ip - Raw IP address
 * @returns {string} Hashed IP
 */
export function hashIP(ip) {
  return createHash("sha256").update(ip).digest("hex").substring(0, 16);
}
