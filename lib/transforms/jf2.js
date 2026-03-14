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
  const jf2 = {
    type: "entry",
    _id: comment._id?.toString() || "",
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
  if (comment.parent_id) {
    jf2.parent_id = comment.parent_id.toString();
  }
  if (comment.is_owner) {
    jf2.is_owner = true;
  }
  return jf2;
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
