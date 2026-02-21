/**
 * Comments controller
 * Dashboard + JF2 API + auth + moderation
 * @module controllers/comments
 */

import {
  insertComment,
  getComments,
  getAllComments,
  getCommentCount,
  getUniqueCommenterCount,
  hideComment,
  restoreComment,
  purgeComment,
  checkRateLimit,
} from "../storage/comment-items.js";
import { commentToJf2, commentsToJf2Feed } from "../transforms/jf2.js";
import {
  discoverEndpoints,
  generatePKCE,
  generateState,
  buildAuthUrl,
  exchangeCode,
  fetchProfile,
  hashIP,
} from "../auth/indieauth.js";
import { sanitizeComment } from "../middleware/sanitize.js";

/**
 * Admin dashboard
 * GET /comments
 */
async function dashboard(request, response) {
  const { application } = request.app.locals;

  try {
    const config = application.comments || {};

    // Stats
    const totalComments = await getCommentCount(application);
    const hiddenComments = await getCommentCount(application, {
      status: "deleted",
    });
    const uniqueCommenters = await getUniqueCommenterCount(application);

    // This week
    const oneWeekAgo = new Date(
      Date.now() - 7 * 24 * 60 * 60 * 1000,
    ).toISOString();
    const thisWeek = await getCommentCount(application, {
      published: { $gte: oneWeekAgo },
      status: "public",
    });

    // Filters
    const statusFilter = request.query.status || "all";
    const targetFilter = request.query.target || null;

    // Pagination
    const page = parseInt(request.query.page, 10) || 1;
    const perPage = 20;
    const skip = (page - 1) * perPage;

    // Get comments (admin sees all statuses)
    const queryOptions = { limit: perPage, skip };
    if (statusFilter !== "all") queryOptions.status = statusFilter;
    if (targetFilter) queryOptions.target = targetFilter;

    const comments = await getAllComments(application, queryOptions);

    // Total for pagination
    const filterQuery = {};
    if (statusFilter !== "all") filterQuery.status = statusFilter;
    const filteredTotal = await getCommentCount(application, filterQuery);
    const totalPages = Math.ceil(filteredTotal / perPage);

    response.render("comments", {
      title: response.__
        ? response.__("comments.title")
        : "Comments",
      config,
      totalComments,
      hiddenComments,
      uniqueCommenters,
      thisWeek,
      comments,
      statusFilter,
      targetFilter,
      page,
      totalPages,
      baseUrl: config.mountPath || "/comments",
    });
  } catch (error) {
    console.error("[Comments] Dashboard error:", error.message);
    response.status(500).render("comments", {
      title: "Comments",
      error: error.message,
      totalComments: 0,
      hiddenComments: 0,
      uniqueCommenters: 0,
      thisWeek: 0,
      comments: [],
      statusFilter: "all",
      page: 1,
      totalPages: 1,
    });
  }
}

/**
 * JF2 API — get comments for a target
 * GET /comments/api/comments?target={url}&limit={n}
 */
async function apiComments(request, response) {
  const { application } = request.app.locals;

  try {
    const target = request.query.target || null;
    const limit = Math.min(parseInt(request.query.limit, 10) || 50, 100);
    const page = parseInt(request.query.page, 10) || 1;
    const skip = (page - 1) * limit;

    const comments = await getComments(application, target, { limit, skip });
    const feed = commentsToJf2Feed(comments);

    response.json(feed);
  } catch (error) {
    console.error("[Comments] API error:", error.message);
    response.status(500).json({ error: "Failed to fetch comments" });
  }
}

/**
 * Start IndieAuth flow
 * POST /comments/api/auth
 * Body: { me: "https://user.example.com" }
 */
async function startAuth(request, response) {
  const { application } = request.app.locals;

  try {
    const me = request.body.me;
    if (!me) {
      return response.status(400).json({ error: "Missing 'me' URL" });
    }

    // Normalize URL
    let meUrl;
    try {
      meUrl = new URL(me.startsWith("http") ? me : `https://${me}`);
    } catch {
      return response.status(400).json({ error: "Invalid URL" });
    }

    // Discover endpoints
    const endpoints = await discoverEndpoints(meUrl.href);

    // Generate PKCE and state
    const { verifier, challenge } = generatePKCE();
    const state = generateState();

    // Store session data
    const sessionsCollection = application.collections.get("comment_sessions");
    const siteUrl = application.publication?.me || application.url;
    const redirectUri = `${siteUrl}${application.comments?.mountPath || "/comments"}/auth/callback`;

    await sessionsCollection.insertOne({
      state,
      code_verifier: verifier,
      authorization_endpoint: endpoints.authorizationEndpoint,
      token_endpoint: endpoints.tokenEndpoint,
      me: meUrl.href,
      redirect_uri: redirectUri,
      client_id: siteUrl,
      return_url: request.body.returnUrl || "/",
      created_at: new Date(),
    });

    // Build auth URL
    const authUrl = buildAuthUrl({
      authorizationEndpoint: endpoints.authorizationEndpoint,
      clientId: siteUrl,
      redirectUri,
      state,
      codeChallenge: challenge,
      me: meUrl.href,
    });

    response.json({ authUrl });
  } catch (error) {
    console.error("[Comments] Auth start error:", error.message);
    response.status(500).json({ error: "Authentication failed to start" });
  }
}

/**
 * IndieAuth callback
 * GET /comments/auth/callback?code={code}&state={state}
 */
async function authCallback(request, response) {
  const { application } = request.app.locals;

  try {
    const { code, state, error: authError } = request.query;

    if (authError) {
      return response.redirect(
        `/?auth_error=${encodeURIComponent(authError)}`,
      );
    }

    if (!code || !state) {
      return response.redirect("/?auth_error=missing_params");
    }

    // Look up session
    const sessionsCollection = application.collections.get("comment_sessions");
    const session = await sessionsCollection.findOne({ state });

    if (!session) {
      return response.redirect("/?auth_error=invalid_state");
    }

    // Exchange code for profile
    const result = await exchangeCode({
      authorizationEndpoint: session.authorization_endpoint,
      code,
      clientId: session.client_id,
      redirectUri: session.redirect_uri,
      codeVerifier: session.code_verifier,
    });

    // Fetch profile info
    const profile = await fetchProfile(result.me);

    // Update session with authenticated user info
    await sessionsCollection.findOneAndUpdate(
      { state },
      {
        $set: {
          authenticated: true,
          user: {
            url: result.me,
            name: profile.name || new URL(result.me).hostname,
            photo: profile.photo || "",
          },
          authenticated_at: new Date(),
        },
      },
    );

    // Set session cookie
    response.cookie("comment_session", state, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 2 * 60 * 60 * 1000, // 2 hours
    });

    // Redirect back to the post
    const returnUrl = session.return_url || "/";
    response.redirect(returnUrl);
  } catch (error) {
    console.error("[Comments] Auth callback error:", error.message);
    response.redirect("/?auth_error=exchange_failed");
  }
}

/**
 * Submit a comment
 * POST /comments/api/submit
 * Body: { content: "...", target: "https://..." }
 * Requires comment_session cookie
 */
async function submit(request, response) {
  const { application } = request.app.locals;

  try {
    const config = application.comments || {};
    const sessionId = request.cookies?.comment_session;

    if (!sessionId) {
      return response.status(401).json({ error: "Please sign in to comment" });
    }

    // Verify session
    const sessionsCollection = application.collections.get("comment_sessions");
    const session = await sessionsCollection.findOne({
      state: sessionId,
      authenticated: true,
    });

    if (!session) {
      return response.status(401).json({ error: "Invalid or expired session" });
    }

    const { content, target } = request.body;

    if (!target) {
      return response.status(400).json({ error: "Missing target URL" });
    }

    // Sanitize content
    const sanitized = sanitizeComment(content, config.maxLength || 2000);
    if (!sanitized.valid) {
      return response.status(400).json({ error: sanitized.error });
    }

    // Check rate limit
    const limits = config.rateLimit || { perHour: 5, perDay: 20 };
    const rateCheck = await checkRateLimit(
      application,
      session.user.url,
      limits,
    );
    if (!rateCheck.allowed) {
      return response.status(429).json({ error: rateCheck.reason });
    }

    // Insert comment
    const comment = await insertComment(application, {
      target,
      author: session.user,
      content: {
        text: sanitized.text,
        html: sanitized.html,
      },
      ip_hash: hashIP(
        request.ip || request.headers["x-forwarded-for"] || "unknown",
      ),
    });

    response.status(201).json({
      success: true,
      comment: commentToJf2(comment),
    });
  } catch (error) {
    console.error("[Comments] Submit error:", error.message);
    response.status(500).json({ error: "Failed to post comment" });
  }
}

/**
 * Check current session
 * GET /comments/api/session
 * Returns user info if authenticated, 401 otherwise
 */
async function session(request, response) {
  const { application } = request.app.locals;

  try {
    const sessionId = request.cookies?.comment_session;
    if (!sessionId) {
      return response.status(401).json({ user: null });
    }

    const sessionsCollection = application.collections.get("comment_sessions");
    const sess = await sessionsCollection.findOne({
      state: sessionId,
      authenticated: true,
    });

    if (!sess) {
      return response.status(401).json({ user: null });
    }

    response.json({ user: sess.user });
  } catch {
    response.status(401).json({ user: null });
  }
}

/**
 * Hide a comment (soft delete)
 * POST /comments/hide
 * Body: { id: "..." }
 */
async function hide(request, response) {
  const { application } = request.app.locals;

  try {
    const { id, action } = request.body;
    if (!id) {
      return response.status(400).redirect(request.get("referer") || "/comments");
    }

    if (action === "restore") {
      await restoreComment(application, id);
    } else {
      await hideComment(application, id);
    }

    response.redirect(request.get("referer") || "/comments");
  } catch (error) {
    console.error("[Comments] Hide error:", error.message);
    response.redirect(request.get("referer") || "/comments");
  }
}

/**
 * Purge a comment (permanent delete)
 * POST /comments/purge
 * Body: { id: "..." }
 */
async function purge(request, response) {
  const { application } = request.app.locals;

  try {
    const { id } = request.body;
    if (!id) {
      return response.status(400).redirect(request.get("referer") || "/comments");
    }

    await purgeComment(application, id);
    response.redirect(request.get("referer") || "/comments");
  } catch (error) {
    console.error("[Comments] Purge error:", error.message);
    response.redirect(request.get("referer") || "/comments");
  }
}

export const commentsController = {
  dashboard,
  apiComments,
  startAuth,
  authCallback,
  submit,
  session,
  hide,
  purge,
};
