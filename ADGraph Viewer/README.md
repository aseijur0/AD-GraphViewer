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

## Optimized core

This edition uses a revisioned in-memory graph index shared by search, the
Inspector, expansion, saved queries, custom queries, rendering, and candidate
guidance. Incoming, outgoing, incident, membership, containment, node-kind,
edge-kind, and high-value lookups are built once per ingestion revision.

Overlapping collector files are merged and duplicate relationship variants are
discarded during ingestion. Computed relationships such as paired-rights
DCSync use the same derived-edge layer as filters, edge search, rendering, and
path analysis.

Saved attack-path queries now use the same relationship allow-list and cost
model as Suggested attack paths, preventing structural hierarchy and incomplete
single-prerequisite relationships from becoming attack steps. Filtering an
existing view reuses the vis-network instance and preserves positions rather
than running a new layout. File parsing runs in a Web Worker when permitted,
with the original parser retained as a compatibility fallback.

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

## Guided analysis

After collection data loads, the **Suggested attack paths** section ranks up to
six candidate routes toward Domain Admins, forest-level privileged groups, and
other high-value targets. Objects marked Owned are always preferred as starting
points. If none are marked, the tool uses clearly labelled low-privilege or
credential-exposure assumptions. Controls can restrict target tiers, maximum
hops, session evidence, inherited rights, cross-domain steps, and assumed
starting points. Results can be ranked for feasibility, target privilege, or
hop count. Each recommendation shows its tier, evidence quality, hop count, and
transparent heuristic cost; clicking it renders only the supporting path.

Selecting a node adds **Candidate path from selected object** to the Inspector.
One primary path is shown and up to two lower-ranked alternatives remain in a
collapsed section. Every option begins at the selected object and ends at a
collected high-value target. The evidence button renders that path without
mixing in suggestions for other objects. Selecting a node or edge keeps the
existing detailed findings and validation-command behavior.

Candidate paths use weighted, loopless search rather than accepting the first
fewest-hop route found. Direct control relationships receive lower costs, while
session evidence, inherited permissions, and referenced-only objects receive
penalties. These values are comparative heuristics—not exploitation
probabilities—and each edge still needs validation against the lab environment.
When the same principal has both `GetChanges` and `GetChangesAll` over one
domain, the guidance engine represents them as a computed DCSync step and shows
that derivation as a validation caveat; neither permission is accepted alone.

Graph history also stores the logical Inspector selection. Using **Back**
restores the node, relationship, saved-query explanation, or candidate-path
explanation that belonged to the restored graph view instead of retaining stale
information from the newer view.

Selecting a relationship shows labelled Source and Destination endpoints plus
a plain-language interpretation of the edge. Counterintuitive BloodHound
directions—such as Computer → User for HasSession—also explain the underlying
privilege-flow meaning and distinguish collected evidence from guaranteed
access.

Recommendations are leads, not proof of exploitability. Session data may be
stale, inherited permissions should be confirmed, referenced-only objects may
be incomplete, and absent collection methods can hide relationships. The tool
does not execute any attack action.

## Test

From the repository root:

```bash
node 2.0/tests/smoke.js
```

No dependencies need to be installed.
