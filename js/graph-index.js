// Revisioned indexes shared by exploration, queries, rendering, and guidance.
// Rebuilt lazily after ingestion changes the graph revision.
var coreGraphIndexCache = null;

function graphRevision(graphRef) {
  return Number(graphRef && graphRef.revision || 0);
}

function invalidateGraphIndexes() {
  coreGraphIndexCache = null;
  if (typeof guidanceIndexCache !== 'undefined') guidanceIndexCache = null;
}

function indexPush(map, key, value) {
  if (!map.has(key)) map.set(key, []);
  map.get(key).push(value);
}

function normalizedNodeFields(node) {
  if (node._normalizedRevision === graphRevision(graph) && node.normalized) return node.normalized;
  var props = node.properties || {}, lower = Object.create(null);
  Object.keys(props).forEach(function (key) { lower[key.toLowerCase()] = props[key]; });
  var name = displayName(node), at = name.lastIndexOf('@');
  var domain = lower.domain || lower.domainsid || (at === -1 ? '' : name.slice(at + 1));
  node.normalized = {
    properties: lower,
    nameLower: name.toLowerCase(), idLower: String(node.id).toLowerCase(),
    domain: domain ? String(domain).toUpperCase() : '',
    enabled: lower.enabled !== false,
    hasSpn: lower.hasspn === true,
    dontReqPreauth: lower.dontreqpreauth === true
  };
  node._normalizedRevision = graphRevision(graph);
  return node.normalized;
}

// Well-known privileged group RIDs (Domain/Enterprise/Schema Admins, built-in
// Administrators and operator groups, DC groups, Key Admins, GPO creators) and
// user RIDs (Administrator, krbtgt) that define the default Tier Zero. Used only
// when a collection carries no explicit high-value flags (e.g. BloodHound CE).
var TIER0_GROUP_RIDS = new Set(['512', '516', '518', '519', '520', '521', '526', '527',
  '544', '548', '549', '550', '551', '552']);
var TIER0_USER_RIDS = new Set(['500', '502']);

function ridFromId(id) {
  var match = String(id).match(/-(\d+)$/);
  return match ? match[1] : '';
}

// AD CS certificate-authority infrastructure is Tier Zero: control of an
// enterprise/root CA, an AIA CA, or the NTAuth store (or the computer hosting
// the CA service) is domain-equivalent (Golden Certificate / ESC7), yet
// collectors do not flag these as high value. Marked unconditionally so
// certificate-services escalation paths reach a target. (BloodHound likewise
// tags this infrastructure Tier Zero.)
var CERT_INFRA_KINDS = { EnterpriseCA: true, RootCA: true, AIACA: true, NTAuthStore: true };

function markCertificateInfraHighValue(graphRef, edgesByKind, highValueIds) {
  var inList = Object.create(null);
  highValueIds.forEach(function (id) { inList[id] = true; });
  function mark(node) {
    if (!node || inList[node.id]) return;
    inList[node.id] = true;
    node.highValue = true;
    node._derivedHighValue = true;
    highValueIds.push(node.id);
  }
  graphRef.nodes.forEach(function (node) { if (CERT_INFRA_KINDS[node.kind]) mark(node); });
  (edgesByKind.get('hostscaservice') || []).forEach(function (edge) { mark(graphRef.nodes.get(edge.from)); });
}

function deriveTierZeroHighValue(graphRef, membersByGroup, highValueIds) {
  var seen = Object.create(null), dcGroupIds = [];
  function mark(node) {
    if (!node || seen[node.id]) return;
    seen[node.id] = true;
    node.highValue = true;
    node._derivedHighValue = true;
    highValueIds.push(node.id);
  }
  graphRef.nodes.forEach(function (node) {
    var rid = ridFromId(node.id);
    if (node.kind === 'Domain') mark(node);
    else if (node.kind === 'Group' && TIER0_GROUP_RIDS.has(rid)) {
      mark(node);
      if (rid === '516' || rid === '521') dcGroupIds.push(node.id);
    } else if (node.kind === 'User' && TIER0_USER_RIDS.has(rid)) mark(node);
    else if (node.kind === 'Computer' && normalizedNodeFields(node).properties.isdc === true) mark(node);
  });
  // Domain controllers are the members of the Domain Controllers (516) and
  // Read-only Domain Controllers (521) groups.
  dcGroupIds.forEach(function (groupId) {
    (membersByGroup.get(groupId) || []).forEach(function (memberId) {
      mark(graphRef.nodes.get(memberId));
    });
  });
}

function getGraphIndex() {
  var revision = graphRevision(graph);
  if (coreGraphIndexCache && coreGraphIndexCache.graph === graph && coreGraphIndexCache.revision === revision) {
    return coreGraphIndexCache;
  }
  var outgoing = new Map(), incoming = new Map(), incident = new Map(), edgesByKind = new Map();
  var nodesByKind = new Map(), membersByGroup = new Map(), groupsByMember = new Map(), childrenByContainer = new Map();
  var searchTrigrams = new Map();
  var highValueIds = [], replication = new Map(), existingDCSync = new Set(), allEdges = graph.edges.slice();
  graph.nodes.forEach(function (node) {
    indexPush(nodesByKind, node.kind || 'Unknown', node.id);
    if (node.highValue) highValueIds.push(node.id);
    var normalized = normalizedNodeFields(node), searchable = normalized.nameLower + ' ' + normalized.idLower;
    var grams = new Set();
    for (var gi = 0; gi + 2 < searchable.length; gi++) grams.add(searchable.slice(gi, gi + 3));
    grams.forEach(function (gram) { indexPush(searchTrigrams, gram, node.id); });
  });
  graph.edges.forEach(function (edge) {
    indexPush(outgoing, edge.from, edge); indexPush(incoming, edge.to, edge);
    indexPush(incident, edge.from, edge); if (edge.to !== edge.from) indexPush(incident, edge.to, edge);
    var lowerKind = String(edge.kind || 'Unknown').toLowerCase();
    indexPush(edgesByKind, lowerKind, edge);
    if (lowerKind === 'memberof') {
      indexPush(membersByGroup, edge.to, edge.from); indexPush(groupsByMember, edge.from, edge.to);
    } else if (lowerKind === 'contains') indexPush(childrenByContainer, edge.from, edge);
    if (lowerKind === 'getchanges' || lowerKind === 'getchangesall') {
      var pairKey = edge.from + '\u0000' + edge.to;
      if (!replication.has(pairKey)) replication.set(pairKey, {});
      replication.get(pairKey)[lowerKind] = edge;
    } else if (lowerKind === 'dcsync') existingDCSync.add(edge.from + '\u0000' + edge.to);
  });
  replication.forEach(function (rights, pairKey) {
    if (!rights.getchanges || !rights.getchangesall || existingDCSync.has(pairKey)) return;
    var parts = pairKey.split('\u0000'), target = graph.nodes.get(parts[1]);
    if (target && target.kind !== 'Domain') return;
    var derived = { from: parts[0], to: parts[1], kind: 'DCSync', category: 'acl', computed: true,
      inherited: !!(rights.getchanges.inherited || rights.getchangesall.inherited),
      evidenceEdges: [rights.getchanges, rights.getchangesall] };
    allEdges.push(derived); indexPush(outgoing, derived.from, derived); indexPush(incoming, derived.to, derived);
    indexPush(incident, derived.from, derived); indexPush(incident, derived.to, derived);
    indexPush(edgesByKind, 'dcsync', derived);
  });
  // BloodHound CE collectors (SharpHound CE, RustHound-CE) no longer emit the
  // `highvalue` property — Tier Zero is tagged server-side at analysis time, so
  // a raw CE collection carries no high-value flags and the attack-path targets
  // (and therefore Suggested Attack Paths) come up empty. When nothing in the
  // collection is flagged high value, derive a Tier-Zero set from well-known
  // privileged RIDs/SIDs so the viewer behaves like it does with legacy data.
  // This only fires as a fallback, so collector-provided flags always win.
  if (!highValueIds.length) deriveTierZeroHighValue(graph, membersByGroup, highValueIds);
  // Always add AD CS CA infrastructure as Tier Zero (control of it is
  // domain-equivalent), regardless of collector-provided high-value flags.
  markCertificateInfraHighValue(graph, edgesByKind, highValueIds);
  // Viewer-side AD CS escalation (ESC) relationships are derived here too, the
  // same way DCSync is: each is pushed into the shared indexes marked
  // computed:true with the raw inputs it was built from preserved.
  if (typeof deriveEscalationEdges === 'function') {
    deriveEscalationEdges({
      nodes: graph.nodes, edgesByKind: edgesByKind,
      pushEdge: function (edge) {
        allEdges.push(edge);
        indexPush(outgoing, edge.from, edge); indexPush(incoming, edge.to, edge);
        indexPush(incident, edge.from, edge); if (edge.to !== edge.from) indexPush(incident, edge.to, edge);
        indexPush(edgesByKind, String(edge.kind).toLowerCase(), edge);
      }
    });
  }
  coreGraphIndexCache = { graph: graph, revision: revision, outgoing: outgoing, incoming: incoming,
    incident: incident, edgesByKind: edgesByKind, nodesByKind: nodesByKind,
    membersByGroup: membersByGroup, groupsByMember: groupsByMember,
    childrenByContainer: childrenByContainer, highValueIds: highValueIds,
    searchTrigrams: searchTrigrams, allEdges: allEdges };
  return coreGraphIndexCache;
}

function incidentEdges(id) { return getGraphIndex().incident.get(id) || []; }
function outgoingEdges(id) { return getGraphIndex().outgoing.get(id) || []; }
function incomingEdges(id) { return getGraphIndex().incoming.get(id) || []; }
