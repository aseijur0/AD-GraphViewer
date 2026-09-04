// Extracted from NewOne/adCodex-cyberpunk.html; kept as a classic browser script.

// ============================================================================
// AD Graph Viewer — app logic
// Core idea: never hand vis-network more than a bounded number of nodes/edges
// at once, AND never draw anything automatically. Loading files always lands
// on a blank canvas; the user decides what to look at via a premade query,
// a search, or an explicit "show entire graph" action. This is what keeps
// a dense real-world domain from becoming an unreadable, tab-locking hairball.
// ============================================================================

var KIND_ORDER = ['User','Group','Computer','Domain','GPO','OU','Container',
  'CertTemplate','EnterpriseCA','RootCA','AIACA','NTAuthStore','IssuancePolicy',
  'ForeignSecurityPrincipal','Unknown'];
var KIND_META = {
  User:      { color:'#3FB8AF', shape:'dot' },
  Group:     { color:'#D9A441', shape:'diamond' },
  Computer:  { color:'#5B8DEF', shape:'square' },
  Domain:    { color:'#9B7FE0', shape:'star' },
  GPO:       { color:'#E0708A', shape:'triangle' },
  OU:        { color:'#8B93A7', shape:'box' },
  Container: { color:'#C9A56B', shape:'triangleDown' },
  CertTemplate:   { color:'#B784E8', shape:'hexagon' },
  EnterpriseCA:   { color:'#F06DAA', shape:'triangle' },
  RootCA:         { color:'#C45DE8', shape:'star' },
  AIACA:          { color:'#9D7BE8', shape:'diamond' },
  NTAuthStore:    { color:'#D95F8D', shape:'box' },
  IssuancePolicy: { color:'#A98BE8', shape:'triangleDown' },
  ForeignSecurityPrincipal: { color:'#7F8CA8', shape:'dot' },
  Unknown:   { color:'#5A6072', shape:'dot' }
};
var CAT_META = {
  structural: { color:'#4A5262' },
  access:     { color:'#4FA3F7' },
  acl:        { color:'#E8895D' },
  adcs:       { color:'#B784E8' }
};
var CAT_PRIORITY = { adcs:0, acl:1, access:2, structural:3 };
function categoryPriority(category) {
  return Object.prototype.hasOwnProperty.call(CAT_PRIORITY, category) ? CAT_PRIORITY[category] : 9;
}

var NEIGHBOR_CAP = 150;            // max relationships drawn around one searched node
var QUERY_TOTAL_CAP = 250;         // max total nodes a premade query will ever draw at once
var CONFIRM_HUGE_THRESHOLD = 3000; // above this, confirm before "show entire graph"

// Core app state. Deliberately `var` (not `const`/`let`) so it lands on `window`
// and is inspectable/scriptable from devtools - useful for the technical
// audience this tool is built for, e.g. `graph.nodes.size` in the console.
var graph = makeGraph();
var activeKinds = new Set(KIND_ORDER);
var activeEdgeCategories = new Set(Object.keys(CAT_META));
var activeEdgeKinds = new Set();
var ownedNodeIds = new Set();
var activeOwnedOnly = false;
var ownedFilterBaseView = null;
var availableEdgeKinds = [];
var edgeKindFiltersInitialized = false;
var network = null;
var currentView = null; // {nodeIds:Set, edges:[...], meta:{centerId?, pinnedIds?, capped?, totalRelCount?, caption?}}
var viewHistory = [];
var suppressHistory = false;
var physicsFrozen = true;
var groupParallelEdges = false;
var expandNodeId = null;
var selectedNodeId = null;
var activeEdgeDirection = 'all'; // all | in | out, relative to edgeDirectionAnchorId
var edgeDirectionAnchorId = null;
var currentVisEdgeMap = {};   // vis edge id → {edge, fromNode, toNode}
var currentNodeDataSet = null;
var currentEdgeDataSet = null;
