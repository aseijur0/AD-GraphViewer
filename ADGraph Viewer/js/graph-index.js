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
