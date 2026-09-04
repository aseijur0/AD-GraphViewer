# ADGraph Optimized

ADGraph Optimized is a database-free, browser-only viewer for SharpHound and
AzureHound JSON/ZIP collections. All collection data remains in memory in the
current browser tab.

## Run

Open `index.html` directly in a modern browser. The application uses classic,
ordered browser scripts, so a local web server and build step are not required.

If the browser restricts local files, serve this directory with any static file
server, for example:

```bash
python3 -m http.server 8000 --directory Optimized
```

Then open `http://localhost:8000`.


## Structure

- `index.html` — application markup and script loading order.
- `css/app.css` — themes, layout, responsive behavior, and component styles.
- `js/bloodhound-parser.js` — BloodHound object detection and normalization.
- `js/graph-store.js` — graph metadata and shared in-memory application state.
- `js/sample-data.js` — built-in demonstration collection.
- `js/utils.js` — shared formatting, theme, and DOM helpers.
- `js/graph-index.js` — revisioned adjacency, membership, containment, type,
  search, and derived-relationship indexes.
- `js/file-ingestion.js` — JSON/ZIP loading and post-ingestion coordination.
- `js/ingestion-worker.js` — optional off-main-thread JSON/ZIP parsing.
- `js/filter-engine.js` — node, relationship, ownership, and direction filters.
- `js/query-engine.js` — saved queries, Cypher-like queries, and path evaluation.
- `js/guidance-engine.js` — contextual next steps and ranked candidate attack paths.
- `js/graph-renderer.js` — vis-network rendering and selective expansion.
- `js/findings.js` — node and relationship security findings.
- `js/inspector.js` — object/relationship inspector and object search.
- `js/workspace.js` — graph actions, export, preferences, and view history.
- `js/app.js` — UI event wiring and application initialization.
- `js/vendor/` — local JSZip and vis-network distributions.
- `tests/smoke.js` — syntax, structure, ingestion, filter, and query checks.

The files intentionally use classic scripts rather than ES modules. This keeps
the application directly openable through `file://` while allowing the existing
shared graph state to remain available across files.


No dependencies need to be installed.
