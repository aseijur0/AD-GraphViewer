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

## Saved query catalogue

The Saved Query menu is grouped by workflow and includes 47 mappings:

- **Attack paths:** shortest paths to Domain Admins/high-value targets, paths
  from owned objects and broad low-privilege groups, paths to other privileged
  groups, a heuristic lowest-cost path view, and attack-path choke points.
- **Credentials:** Kerberoastable and AS-REP roastable users, old active-user
  passwords, and principals able to read LAPS or gMSA passwords.
- **Object control:** DCSync, dangerous direct rights, and dangerous rights
  assigned to broad groups such as Domain Users or Authenticated Users.
- **Sessions and lateral movement:** remote administration edges, computer-to-
  computer administration, privileged sessions, and privileged sessions on
  non-domain-controller systems.
- **Delegation:** unconstrained delegation, constrained delegation, RBCD, and
  privileged sessions exposed on unconstrained-delegation hosts.
- **Identity hygiene:** privileged/high-value inventory, privileged users not
  in Protected Users, inactive enabled privileged accounts, SID history, and
  unsupported active Windows hosts that have incoming access paths.
- **Policy and hierarchy:** writable GPO impact, writable OU/container impact,
  deep group nesting, and circular group nesting.
- **Domains and trusts:** trust maps, same-forest trusts, cross-domain group
  membership, and ACLs that cross domain boundaries.
- **AD CS:** PKI inventory, computed ESC paths, ESC1/3/4, CA control, and
  certificate-services relay paths.

Mappings depend on the corresponding SharpHound collection methods and fields.
A query with no matching collected evidence reports no results; it does not
infer missing relationships.

Selecting a saved query also shows a short explanation in the Inspector: what
the mapping does, why it is useful, and which collection data it needs. Selecting
a node or relationship replaces that explanation with the normal object or edge
details.


No dependencies need to be installed.
