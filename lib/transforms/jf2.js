/**
 * Comment to JF2 transform
 * @module transforms/jf2
 */

/**
 * Convert a comment document to JF2 entry
 * @param {object} comment - MongoDB comment document
 * @returns {object} JF2 entry
 */
export function commentToJf2(comment) {
  return {
    type: "entry",
    author: {
      type: "card",
      name: comment.author?.name || "",
      url: comment.author?.url || "",
      photo: comment.author?.photo || "",
    },
    content: {
      text: comment.content?.text || "",
      html: comment.content?.html || "",
    },
    published: comment.published,
    "comment-target": comment.target,
  };
}

/**
 * Wrap comments in a JF2 feed
 * @param {Array} comments - Array of comment documents
 * @returns {object} JF2 feed
 */
export function commentsToJf2Feed(comments) {
  return {
    type: "feed",
    name: "Comments",
    children: comments.map(commentToJf2),
  };
}
