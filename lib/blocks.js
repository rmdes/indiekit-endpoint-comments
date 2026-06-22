/**
 * Comments v2 block declaration (Phase 7b — plugin block ownership).
 *
 * The `recent-comments` sidebar widget was a site-config BUILTIN_BLOCKS seed
 * (requiresPlugin null, gated only by the theme's legacy widgetPluginRequirements
 * render-map). Declaring it here makes site-config's scanPlugins stamp
 * `sourcePlugin` → `requiresPlugin` ("Comments endpoint"), so the block is
 * properly plugin-gated (theme ENDPOINT_SLUGS maps it to the `comments` loadout
 * slug). scanPlugins precedence is `built-in < plugin blocks`, so this entry
 * OVERWRITES the builtin seed on sites where the plugin is loaded; the seed
 * itself is removed from site-config in Phase 7d alongside the legacy-map bridge.
 *
 * Descriptor is byte-faithful to the BUILTIN_BLOCKS entry (id/label/icon/
 * placement/data unchanged) so the catalog is identical — only its provenance
 * changes. Bespoke template: the theme owns `components/widgets/recent-comments.njk`
 * (no generic `render.renderer`); `data.source:"api"` documents the runtime fetch.
 *
 * @module lib/blocks
 */

/** @type {Array<object>} */
export const COMMENTS_BLOCKS = [
  {
    id: "recent-comments",
    version: 1,
    label: "Recent Comments",
    description: "Latest IndieAuth comments",
    icon: "message-square",
    category: "social",
    placement: { regions: ["sidebar"], surfaces: ["homepage", "postType"] },
    multiple: false,
    data: { source: "api" },
    schema: { type: "object", additionalProperties: false, properties: {} },
  },
];
