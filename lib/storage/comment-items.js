/**
 * Comment items storage
 * MongoDB CRUD for comments with indexes
 * @module storage/comment-items
 */

/**
 * Get the comments collection
 * @param {object} application - Indiekit application
 * @returns {object} MongoDB collection
 */
function getCollection(application) {
  return application.collections.get("comments");
}

/**
 * Create indexes for the comments collection
 * @param {object} Indiekit - Indiekit instance
 */
export async function createIndexes(Indiekit) {
  const collection = Indiekit.config.application.collections?.get("comments");
  if (collection) {
    await collection.createIndex(
      { target: 1, published: -1 },
      { name: "target_published" },
    );

    await collection.createIndex(
      { "author.url": 1, published: -1 },
      { name: "author_published" },
    );

    await collection.createIndex(
      { status: 1 },
      { name: "status_filter" },
    );
  }

  // TTL index for session auto-expiry (2 hours)
  const sessionsCollection =
    Indiekit.config.application.collections?.get("comment_sessions");
  if (sessionsCollection) {
    await sessionsCollection.createIndex(
      { created_at: 1 },
      { expireAfterSeconds: 7200, name: "session_ttl" },
    );
  }
}

/**
 * Insert a new comment
 * @param {object} application - Indiekit application
 * @param {object} comment - Comment data
 * @returns {Promise<object>} Inserted comment
 */
export async function insertComment(application, comment) {
  const collection = getCollection(application);
  const doc = {
    ...comment,
    published: new Date().toISOString(),
    status: "public",
  };
  // Preserve parent_id if provided (for threaded replies)
  if (comment.parent_id) {
    const { ObjectId } = await import("mongodb");
    doc.parent_id = new ObjectId(comment.parent_id);
  }
  const result = await collection.insertOne(doc);
  return { ...doc, _id: result.insertedId };
}

/**
 * Get comments for a target URL
 * @param {object} application - Indiekit application
 * @param {string} [targetUrl] - Filter by target URL (omit for all)
 * @param {object} [options] - Query options
 * @returns {Promise<Array>} Array of comments
 */
export async function getComments(application, targetUrl, options = {}) {
  const collection = getCollection(application);
  const query = {};

  if (targetUrl) {
    // Match with and without trailing slash
    const normalized = targetUrl.endsWith("/")
      ? targetUrl.slice(0, -1)
      : targetUrl;
    query.target = { $in: [normalized, normalized + "/"] };
  }

  if (options.status) {
    query.status = options.status;
  } else {
    query.status = "public";
  }

  let cursor = collection.find(query).sort({ published: -1 });

  if (options.skip) cursor = cursor.skip(options.skip);
  cursor = cursor.limit(options.limit || 50);

  return cursor.toArray();
}

/**
 * Get all comments (admin, includes hidden)
 * @param {object} application - Indiekit application
 * @param {object} [options] - Query options
 * @returns {Promise<Array>} Array of comments
 */
export async function getAllComments(application, options = {}) {
  const collection = getCollection(application);
  const query = {};

  if (options.status) query.status = options.status;
  if (options.target) {
    const normalized = options.target.endsWith("/")
      ? options.target.slice(0, -1)
      : options.target;
    query.target = { $in: [normalized, normalized + "/"] };
  }

  let cursor = collection.find(query).sort({ published: -1 });

  if (options.skip) cursor = cursor.skip(options.skip);
  cursor = cursor.limit(options.limit || 50);

  return cursor.toArray();
}

/**
 * Get comment count (optionally filtered)
 * @param {object} application - Indiekit application
 * @param {object} [filter] - MongoDB filter
 * @returns {Promise<number>} Count
 */
export async function getCommentCount(application, filter = {}) {
  const collection = getCollection(application);
  return collection.countDocuments(filter);
}

/**
 * Get unique commenter count
 * @param {object} application - Indiekit application
 * @returns {Promise<number>} Count of unique author URLs
 */
export async function getUniqueCommenterCount(application) {
  const collection = getCollection(application);
  const result = await collection.distinct("author.url", { status: "public" });
  return result.length;
}

/**
 * Hide a comment (soft delete)
 * @param {object} application - Indiekit application
 * @param {string} commentId - MongoDB ObjectId as string
 * @returns {Promise<object>} Updated document
 */
export async function hideComment(application, commentId) {
  const collection = getCollection(application);
  const { ObjectId } = await import("mongodb");
  return collection.findOneAndUpdate(
    { _id: new ObjectId(commentId) },
    { $set: { status: "deleted" } },
    { returnDocument: "after" },
  );
}

/**
 * Restore a hidden comment
 * @param {object} application - Indiekit application
 * @param {string} commentId - MongoDB ObjectId as string
 * @returns {Promise<object>} Updated document
 */
export async function restoreComment(application, commentId) {
  const collection = getCollection(application);
  const { ObjectId } = await import("mongodb");
  return collection.findOneAndUpdate(
    { _id: new ObjectId(commentId) },
    { $set: { status: "public" } },
    { returnDocument: "after" },
  );
}

/**
 * Purge a comment (permanent delete)
 * @param {object} application - Indiekit application
 * @param {string} commentId - MongoDB ObjectId as string
 * @returns {Promise<object>} Delete result
 */
export async function purgeComment(application, commentId) {
  const collection = getCollection(application);
  const { ObjectId } = await import("mongodb");
  return collection.deleteOne({ _id: new ObjectId(commentId) });
}

/**
 * Check rate limit for an author
 * @param {object} application - Indiekit application
 * @param {string} authorUrl - Author URL
 * @param {object} limits - { perHour, perDay }
 * @returns {Promise<{allowed: boolean, reason?: string}>}
 */
export async function checkRateLimit(application, authorUrl, limits) {
  const collection = getCollection(application);
  const now = new Date();

  const oneHourAgo = new Date(now - 60 * 60 * 1000).toISOString();
  const hourCount = await collection.countDocuments({
    "author.url": authorUrl,
    published: { $gte: oneHourAgo },
  });

  if (hourCount >= limits.perHour) {
    return { allowed: false, reason: "Hourly limit reached" };
  }

  const oneDayAgo = new Date(now - 24 * 60 * 60 * 1000).toISOString();
  const dayCount = await collection.countDocuments({
    "author.url": authorUrl,
    published: { $gte: oneDayAgo },
  });

  if (dayCount >= limits.perDay) {
    return { allowed: false, reason: "Daily limit reached" };
  }

  return { allowed: true };
}
