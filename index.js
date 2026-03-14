import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import cookieParser from "cookie-parser";

import { commentsController } from "./lib/controllers/comments.js";
import { createIndexes } from "./lib/storage/comment-items.js";

const defaults = {
  mountPath: "/comments",
  rateLimit: {
    perHour: 5,
    perDay: 20,
  },
  maxLength: 2000,
  relMeAuthFallback: true,
};

const router = express.Router();

export default class CommentsEndpoint {
  name = "Comments endpoint";

  constructor(options = {}) {
    this.options = { ...defaults, ...options };
    this.mountPath = this.options.mountPath;
  }

  get localesDirectory() {
    return path.join(path.dirname(fileURLToPath(import.meta.url)), "locales");
  }

  get navigationItems() {
    return {
      href: this.options.mountPath,
      text: "comments.title",
      requiresDatabase: true,
    };
  }

  get routes() {
    router.get("/", commentsController.dashboard);
    router.post("/hide", commentsController.hide);
    router.post("/purge", commentsController.purge);
    return router;
  }

  get routesPublic() {
    const publicRouter = express.Router();
    publicRouter.use(cookieParser());
    publicRouter.get("/api/comments", commentsController.apiComments);
    publicRouter.get("/api/session", commentsController.session);
    publicRouter.get("/api/is-owner", commentsController.isOwner);
    publicRouter.post("/api/submit", commentsController.submit);
    publicRouter.post("/api/reply", commentsController.submitReply);
    publicRouter.get("/api/owner-replies", commentsController.ownerReplies);
    publicRouter.post("/api/auth", commentsController.startAuth);
    publicRouter.get("/auth/callback", commentsController.authCallback);
    return publicRouter;
  }

  init(Indiekit) {
    Indiekit.addCollection("comments");
    Indiekit.addCollection("comment_sessions");
    Indiekit.addEndpoint(this);

    if (!Indiekit.config.application.comments) {
      Indiekit.config.application.comments = this.options;
    }

    if (Indiekit.database) {
      createIndexes(Indiekit).catch((error) => {
        console.warn("[Comments] Index creation failed:", error.message);
      });
    }
  }
}
