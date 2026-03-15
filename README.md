# @rmdes/indiekit-endpoint-comments

Comment endpoint for [Indiekit](https://getindiekit.com/). Allows visitors to authenticate via IndieAuth and post comments on blog posts. Site owners can reply to comments from the admin session.

## Features

- **IndieAuth authentication** — visitors sign in with their personal URL via IndieAuth/PKCE
- **Comment submission** — authenticated visitors can post comments on any page
- **Owner replies** — site owner can reply to native comments from the admin session
- **Rate limiting** — per-user rate limits (configurable per hour/per day)
- **Content sanitization** — HTML sanitization with configurable max length
- **Admin moderation** — hide (soft delete), restore, and purge comments
- **JF2 API** — comments served in JF2 feed format for frontend consumption

## Installation

```bash
npm install @rmdes/indiekit-endpoint-comments
```

```javascript
// indiekit.config.js
import CommentsEndpoint from "@rmdes/indiekit-endpoint-comments";

export default {
  plugins: [
    new CommentsEndpoint({
      mountPath: "/comments",
      maxLength: 2000,
      rateLimit: { perHour: 5, perDay: 20 },
    }),
  ],
};
```

## API

### Public Routes (no authentication required)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/comments/api/comments?target={url}` | Get comments for a target URL (JF2 feed) |
| GET | `/comments/api/session` | Check current IndieAuth session |
| GET | `/comments/api/is-owner` | Check if visitor is the site owner (admin session) |
| POST | `/comments/api/submit` | Submit a comment (requires IndieAuth session) |
| POST | `/comments/api/reply` | Submit an owner reply to a comment (requires admin session) |
| POST | `/comments/api/auth` | Start IndieAuth flow |
| GET | `/comments/auth/callback` | IndieAuth callback handler |

### Admin Routes (require Indiekit authentication)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/comments` | Admin dashboard with stats and moderation |
| POST | `/comments/hide` | Soft-delete a comment |
| POST | `/comments/purge` | Permanently delete a comment |

### Owner Reply (POST /comments/api/reply)

Allows the site owner to reply to native comments. Requires an active Indiekit admin session (not an IndieAuth comment session).

**Request:**

```json
{
  "parent_id": "comment-id-123",
  "content": "Thanks for the comment!",
  "target": "https://example.com/posts/hello/"
}
```

**Response:**

```json
{
  "success": true,
  "comment": {
    "type": "entry",
    "author": {
      "name": "Site Owner",
      "url": "https://example.com",
      "photo": "https://..."
    },
    "content": {
      "text": "Thanks for the comment!",
      "html": "<p>Thanks for the comment!</p>"
    },
    "published": "2026-03-15T12:00:00.000Z"
  }
}
```

### Owner Detection (GET /comments/api/is-owner)

Returns owner status and available syndication targets for the reply-to-interactions feature. Used by the frontend to show reply buttons on interactions.

**Response (when owner):**

```json
{
  "isOwner": true,
  "name": "Ricardo Mendes",
  "url": "https://rmendes.net",
  "photo": "https://...",
  "syndicationTargets": {
    "bluesky": "https://bsky.social",
    "mastodon": "https://indieweb.social"
  }
}
```

The `syndicationTargets` map is auto-detected from Indiekit's registered syndicators. The frontend uses these to route replies to the correct platform via Micropub.

## Architecture

### Comment Types

This plugin handles two distinct reply flows:

| Flow | Trigger | Route | Session |
|------|---------|-------|---------|
| **Visitor comment** | Visitor submits via comment form | `POST /api/submit` | IndieAuth comment session |
| **Owner reply to comment** | Owner replies to a native comment | `POST /api/reply` | Indiekit admin session |

### Reply-to-Interactions (Micropub flow)

When the site owner replies to platform interactions (Mastodon replies, Bluesky mentions, IndieWeb webmentions), the reply goes through Micropub — **not** through this plugin. The frontend posts to `/micropub` with `in-reply-to` set to the interaction's URL and optional `mp-syndicate-to` for platform-specific threading.

This separation exists because:
- **Native comments** are stored in the `comments` collection and managed by this plugin
- **Platform interactions** are stored in the `conversation_items` collection by `@rmdes/indiekit-endpoint-conversations`
- **Owner replies to interactions** are Micropub posts stored in the `posts` collection

### Collections

| Collection | Purpose |
|------------|---------|
| `comments` | Native visitor comments |
| `comment_sessions` | IndieAuth session state (PKCE, tokens) |

### Dependencies

- **`indiekit-eleventy-theme`** — The theme's `comments.js` provides the Alpine.js comment form, IndieAuth flow, and inline reply UI. `webmentions.js` provides reply buttons on platform interactions.
- **`@rmdes/indiekit-endpoint-conversations`** — Handles platform interactions (Mastodon/Bluesky/AP). Owner replies to platform interactions go through Micropub, and `conversations` enriches its API with those replies for frontend threading.

## License

MIT
