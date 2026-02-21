/**
 * Content sanitization for comments
 * @module middleware/sanitize
 */

/**
 * Convert plain text to sanitized HTML
 * Only allows: bold (**text**), italic (*text*), links [text](url)
 * All other HTML is escaped.
 * @param {string} text - Plain text input
 * @returns {string} Sanitized HTML
 */
export function textToHtml(text) {
  if (!text) return "";

  // Escape HTML entities first
  let html = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

  // Convert markdown links [text](url) — only allow http/https
  html = html.replace(
    /\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g,
    '<a href="$2" rel="nofollow ugc" target="_blank">$1</a>',
  );

  // Convert bold **text**
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");

  // Convert italic *text* (but not inside already-processed bold)
  html = html.replace(
    /(?<!\*)\*(?!\*)([^*]+)(?<!\*)\*(?!\*)/g,
    "<em>$1</em>",
  );

  // Convert newlines to <br>
  html = html.replace(/\n/g, "<br>");

  // Wrap in paragraph
  return `<p>${html}</p>`;
}

/**
 * Validate and sanitize comment content
 * @param {string} text - Raw input
 * @param {number} maxLength - Maximum character count
 * @returns {{valid: boolean, text: string, html: string, error?: string}}
 */
export function sanitizeComment(text, maxLength = 2000) {
  if (!text || !text.trim()) {
    return { valid: false, text: "", html: "", error: "Comment cannot be empty" };
  }

  const trimmed = text.trim();

  if (trimmed.length > maxLength) {
    return {
      valid: false,
      text: trimmed,
      html: "",
      error: `Comment exceeds maximum length of ${maxLength} characters`,
    };
  }

  return {
    valid: true,
    text: trimmed,
    html: textToHtml(trimmed),
  };
}
