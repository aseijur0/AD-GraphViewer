// Extracted from NewOne/adCodex-cyberpunk.html; kept as a classic browser script.

// ---------------------------------------------------------------------------
// premade queries - each `run()` returns either:
//   { nodeIds:Set, edges:[...], caption:'...', pinnedIds?:Set }
//   { empty:true, caption:'...' }               (no matches found)
//   null                                         (query not applicable, e.g. no such group)
// All of them go through the same NEIGHBOR_CAP/QUERY_TOTAL_CAP-bounded helpers
// and the same drawGraph() as manual exploration, so results can never be
// bigger than what the tool can render smoothly.
// ---------------------------------------------------------------------------
function findGroupsByPrefix(prefix) {
  var out = [];
  (getGraphIndex().nodesByKind.get('Group') || []).forEach(function (id) {
    var n = graph.nodes.get(id);
    if (displayName(n).toUpperCase().indexOf(prefix) === 0) out.push(n.id);
  });
  return out;
}

// direct members of the given group id(s), plus the group(s) themselves - nested
// group membership doesn't need separate handling here, since a nested group is
// itself a direct member and the caller (e.g. the BFS below) will walk into it
function expandGroupMembers(groupIds) {
  var out = new Set(groupIds);
  groupIds.forEach(function (groupId) {
    (getGraphIndex().membersByGroup.get(groupId) || []).forEach(function (id) { out.add(id); });
  });
  return Array.from(out);
}

function expandSeedSet(seedIds, perNodeCap) {
  perNodeCap = perNodeCap || 100;
  var perNodeCapped = false;
  var relatedCache = new Map();
  function relatedTo(id) {
    if (relatedCache.has(id)) return relatedCache.get(id);
    var related = incidentEdges(id).slice();
    related.sort(function (a, b) { return categoryPriority(a.category) - categoryPriority(b.category); });
    if (related.length > perNodeCap) perNodeCapped = true;
    var result = related.slice(0, perNodeCap); relatedCache.set(id, result); return result;
  }
  var nodeIds = new Set(seedIds);
  seedIds.forEach(function (id) { relatedTo(id).forEach(function (e) { nodeIds.add(e.from); nodeIds.add(e.to); }); });

  var overallCapped = nodeIds.size > QUERY_TOTAL_CAP;
  if (overallCapped) {
    var keep = new Set(seedIds);
    for (var id of nodeIds) { if (keep.size >= QUERY_TOTAL_CAP) break; keep.add(id); }
    nodeIds = keep;
  }
  var edges = [];
  var seenEdgeKeys = new Set();
  seedIds.forEach(function (id) {
    relatedTo(id).forEach(function (e) {
      if (!nodeIds.has(e.from) || !nodeIds.has(e.to)) return;
      var key = edgeIdentityKey(e.from, e.to, e.kind);
      if (seenEdgeKeys.has(key)) return;
      seenEdgeKeys.add(key); edges.push(e);
    });
  });
  return { nodeIds: nodeIds, edges: edges, capped: overallCapped || perNodeCapped };
}

function flatFilterResult(ids, caption) {
  var capped = ids.length > QUERY_TOTAL_CAP;
  var shown = capped ? ids.slice(0, QUERY_TOTAL_CAP) : ids;
  var nodeIds = new Set(shown);
  var edges = graph.edges.filter(function (e) { return nodeIds.has(e.from) && nodeIds.has(e.to); });
  return {
    nodeIds: nodeIds, edges: edges, pinnedIds: nodeIds,
    caption: caption + ' (' + shown.length + (capped ? ' of ' + ids.length + ', truncated)' : ')')
  };
}

// Multi-source shortest paths TO a set of targets: BFS from every target
// simultaneously, walking edges backward. The resulting parent pointers,
// followed forward, give the shortest real (directed) path from any
// reachable node to some node in targetIds.
function reverseBFSFromTargets(targetIds, attackOnly) {
  var revAdj = attackOnly ? guidanceIndexes().incoming : getGraphIndex().incoming;
  var dist = new Map();
  var parent = new Map(); // nodeId -> {edge, next} : from nodeId, follow edge to reach `next` (closer to target)
  var queue = [];
  targetIds.forEach(function (t) { if (!dist.has(t)) { dist.set(t, 0); queue.push(t); } });
  var qi = 0;
  while (qi < queue.length) {
    var cur = queue[qi++];
    var incoming = revAdj.get(cur) || [];
    for (var i = 0; i < incoming.length; i++) {
      var edge = incoming[i], nb = edge.from;
      if (dist.has(nb)) continue;
      dist.set(nb, dist.get(cur) + 1);
      parent.set(nb, { edge: edge, next: cur });
      queue.push(nb);
    }
  }
  return { dist: dist, parent: parent };
}

// Walks parent-chains back to the target set for the given (or all reachable)
// source nodes, shortest paths first, stopping once QUERY_TOTAL_CAP distinct
// nodes would be exceeded - so if a domain has poor hygiene and *everything*
// can reach the target, we still show the most directly actionable paths
// rather than truncating arbitrarily or silently blowing past the cap.
function extractPathsToTargets(dist, parent, sourceIds, totalCap) {
  var candidates = (sourceIds ? sourceIds.filter(function (s) { return dist.has(s); }) : Array.from(dist.keys()));
  candidates.sort(function (a, b) { return dist.get(a) - dist.get(b); });

  var nodeIds = new Set();
  var edges = [];
  var seenEdgeKeys = new Set();
  var capped = false;

  for (var ci = 0; ci < candidates.length; ci++) {
    var s = candidates[ci];
    var pathNodes = [s];
    var pathEdges = [];
    var cur = s, hops = 0;
    while (parent.has(cur) && hops < 100) {
      var step = parent.get(cur);
      pathEdges.push(step.edge);
      pathNodes.push(step.next);
      cur = step.next;
      hops++;
    }
    var newCount = 0;
    for (var pi = 0; pi < pathNodes.length; pi++) { if (!nodeIds.has(pathNodes[pi])) newCount++; }
    if (nodeIds.size + newCount > totalCap) { capped = true; break; }
    pathNodes.forEach(function (id) { nodeIds.add(id); });
    pathEdges.forEach(function (e) {
      var key = edgeIdentityKey(e.from, e.to, e.kind);
      if (!seenEdgeKeys.has(key)) { seenEdgeKeys.add(key); edges.push(e); }
    });
  }
  return { nodeIds: nodeIds, edges: edges, capped: capped, totalCandidates: candidates.length };
}

var ADCS_KINDS = new Set(['CertTemplate','EnterpriseCA','RootCA','AIACA','NTAuthStore','IssuancePolicy']);
function resultFromEdges(edges, caption) {
  var nodeIds = new Set(), shown = [], capped = false;
  edges.forEach(function (edge) {
    var additions = (nodeIds.has(edge.from) ? 0 : 1) + (nodeIds.has(edge.to) ? 0 : 1);
    if (nodeIds.size + additions > QUERY_TOTAL_CAP) { capped = true; return; }
    nodeIds.add(edge.from); nodeIds.add(edge.to); shown.push(edge);
  });
  if (!shown.length) return null;
  return { nodeIds: nodeIds, edges: shown, pinnedIds: nodeIds, caption: caption + (capped ? ' (truncated)' : '') };
}

function adcsOverviewResult() {
  var ids = [];
  graph.nodes.forEach(function (node) { if (ADCS_KINDS.has(node.kind)) ids.push(node.id); });
  if (!ids.length) return null;
  var capped = ids.length > QUERY_TOTAL_CAP;
  var nodeIds = new Set(ids.slice(0, QUERY_TOTAL_CAP));
  var edges = graph.edges.filter(function (edge) {
    return nodeIds.has(edge.from) && nodeIds.has(edge.to);
  });
  return { nodeIds: nodeIds, edges: edges, pinnedIds: nodeIds,
    caption: 'AD CS / PKI objects and collected relationships' + (capped ? ' (truncated)' : '') };
}

function potentialESC1Result() {
  var publishedByTemplate = new Map();
  (getGraphIndex().edgesByKind.get('publishedto') || []).forEach(function (edge) {
    if (!publishedByTemplate.has(edge.from)) publishedByTemplate.set(edge.from, []);
    publishedByTemplate.get(edge.from).push(edge);
  });
  var evidence = [];
  (getGraphIndex().edgesByKind.get('enroll') || []).forEach(function (edge) {
    var template = graph.nodes.get(edge.to), props = template && template.properties || {};
    if (!template || template.kind !== 'CertTemplate') return;
    if (props.enrolleesuppliessubject !== true || props.authenticationenabled !== true ||
        props.requiresmanagerapproval === true || Number(props.authorizedsignatures || 0) > 0) return;
    var published = publishedByTemplate.get(template.id) || [];
    if (!published.length) return;
    evidence.push(edge);
    published.forEach(function (item) { evidence.push(item); });
  });
  return resultFromEdges(evidence, 'Potential ESC1 enrollment paths (template prerequisites + publication)');
}

function adcsControlResult(targetKind, edgePattern, caption) {
  var edges = graph.edges.filter(function (edge) {
    var target = graph.nodes.get(edge.to);
    return target && target.kind === targetKind && edgePattern.test(String(edge.kind || ''));
  });
  return resultFromEdges(edges, caption);
}

var DANGEROUS_RIGHTS = /^(GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|ForceChangePassword|AllExtendedRights|AddMember|AddSelf|WriteSPN|AddKeyCredentialLink|WriteGPLink)$/i;
var LATERAL_RIGHTS = /^(AdminTo|CanRDP|CanPSRemote|ExecuteDCOM)$/i;
var OBJECT_CONTROL_RIGHTS = /^(GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|AllExtendedRights|WriteGPLink)$/i;
var PRIVILEGED_GROUP_RIDS = new Set(['512', '518', '519', '544', '548', '549', '550', '551', '552']);

function propertyValue(node, names) {
  if (!node) return undefined;
  var props = normalizedNodeFields(node).properties;
  for (var i = 0; i < names.length; i++) {
    var wanted = names[i].toLowerCase();
    if (Object.prototype.hasOwnProperty.call(props, wanted)) return props[wanted];
  }
  return undefined;
}

function nodeDomain(node) {
  // Prefer the DNS domain name. Comparing a domain object's SID with a
  // principal's DNS-domain property would otherwise make same-domain ACLs
  // look cross-domain.
  return node ? normalizedNodeFields(node).domain : '';
}

function isEnabledNode(node) {
  return propertyValue(node, ['enabled']) !== false;
}

function groupRid(node) {
  var sid = String(propertyValue(node, ['objectid', 'objectidentifier', 'sid']) || node.id || '');
  var match = sid.match(/-(\d+)$/);
  return match ? match[1] : '';
}

function groupIdsByRids(rids) {
  var wanted = new Set(rids.map(String)), out = [];
  (getGraphIndex().nodesByKind.get('Group') || []).forEach(function (id) {
    var node = graph.nodes.get(id);
    if (wanted.has(groupRid(node))) out.push(node.id);
  });
  return out;
}

function nestedMembers(groupIds) {
  var members = new Set(groupIds), queue = groupIds.slice(), qi = 0;
  var membersByGroup = getGraphIndex().membersByGroup;
  while (qi < queue.length) {
    (membersByGroup.get(queue[qi++]) || []).forEach(function (id) {
      if (!members.has(id)) { members.add(id); queue.push(id); }
    });
  }
  return members;
}

function privilegedPrincipalIds() {
  var groupIds = groupIdsByRids(Array.from(PRIVILEGED_GROUP_RIDS));
  graph.nodes.forEach(function (node) {
    if (node.kind === 'Group' && node.highValue && groupIds.indexOf(node.id) === -1) groupIds.push(node.id);
  });
  return nestedMembers(groupIds);
}

function highValueIds() {
  return getGraphIndex().highValueIds.slice();
}

function pathResult(sourceIds, targetIds, caption) {
  if (!sourceIds.length || !targetIds.length) return null;
  var targets = new Set(targetIds);
  var usefulSources = sourceIds.filter(function (id) { return !targets.has(id); });
  var bfs = reverseBFSFromTargets(targetIds, true);
  var result = extractPathsToTargets(bfs.dist, bfs.parent, usefulSources, QUERY_TOTAL_CAP);
  if (!result.edges.length) return { empty: true, caption: 'No ' + caption.toLowerCase() + ' found in the loaded data.' };
  var pinned = new Set(targetIds);
  usefulSources.forEach(function (id) { if (result.nodeIds.has(id)) pinned.add(id); });
  return { nodeIds: result.nodeIds, edges: result.edges, pinnedIds: pinned,
    caption: caption + (result.capped ? ' (truncated)' : '') };
}

function weightedPathResult(sourceIds, targetIds, caption) {
  if (!sourceIds.length || !targetIds.length) return null;
  var distances = new Map(), previous = new Map(), open = [], adjacency = guidanceIndexes().outgoing;
  sourceIds.forEach(function (id) {
    if (graph.nodes.has(id)) { distances.set(id, 0); heapPush(open, { nodeId: id, priority: 0 }); }
  });
  var settled = new Set();
  while (open.length && settled.size < QUERY_TOTAL_CAP * 20) {
    var queued = heapPop(open), current = queued.nodeId;
    if (queued.priority !== distances.get(current)) continue;
    if (settled.has(current)) continue;
    settled.add(current);
    (adjacency.get(current) || []).forEach(function (edge) {
      var proposed = distances.get(current) + guidanceEdgeWeight(edge);
      if (!distances.has(edge.to) || proposed < distances.get(edge.to)) {
        distances.set(edge.to, proposed);
        previous.set(edge.to, edge);
        heapPush(open, { nodeId: edge.to, priority: proposed });
      }
    });
  }
  var reachable = targetIds.filter(function (id) { return distances.has(id) && distances.get(id) > 0; })
    .sort(function (a, b) { return distances.get(a) - distances.get(b); });
  if (!reachable.length) return { empty: true, caption: 'No ' + caption.toLowerCase() + ' found in the loaded data.' };
  var nodeIds = new Set(), edges = [], seen = new Set();
  reachable.forEach(function (target) {
    var current = target, path = [], guard = 0;
    while (previous.has(current) && guard++ < 100) {
      var edge = previous.get(current); path.push(edge); current = edge.from;
    }
    var pathIds = [target]; path.forEach(function (edge) { pathIds.push(edge.from); });
    var additions = pathIds.filter(function (id) { return !nodeIds.has(id); }).length;
    if (nodeIds.size + additions > QUERY_TOTAL_CAP) return;
    pathIds.forEach(function (id) { nodeIds.add(id); });
    path.reverse().forEach(function (edge) {
      var key = edgeIdentityKey(edge.from, edge.to, edge.kind);
      if (!seen.has(key)) { seen.add(key); edges.push(edge); }
    });
  });
  return { nodeIds: nodeIds, edges: edges, pinnedIds: new Set(targetIds),
    caption: caption + ' (heuristic relationship cost)' };
}

function edgesWithMembershipContext(matchedEdges, principalIds, caption) {
  var evidence = matchedEdges.slice();
  principalIds.forEach(function (id) {
    outgoingEdges(id).forEach(function (edge) { if (edge.kind === 'MemberOf') evidence.push(edge); });
  });
  return resultFromEdges(evidence, caption);
}

function timestampSeconds(value) {
  if (value == null || value === '') return null;
  if (typeof value === 'string' && !/^\d+$/.test(value)) {
    var parsed = Date.parse(value);
    return isNaN(parsed) ? null : Math.floor(parsed / 1000);
  }
  var numeric = Number(value);
  if (!isFinite(numeric) || numeric <= 0) return null;
  if (numeric > 116444736000000000) return Math.floor(numeric / 10000000 - 11644473600);
  if (numeric > 1000000000000) return Math.floor(numeric / 1000);
  return Math.floor(numeric);
}

function containmentClosure(seedIds, includeSeeds) {
  var ids = new Set(includeSeeds === false ? [] : seedIds), edges = [], queue = seedIds.slice(), qi = 0;
  while (qi < queue.length && ids.size < QUERY_TOTAL_CAP) {
    var current = queue[qi++];
    (getGraphIndex().childrenByContainer.get(current) || []).forEach(function (edge) {
      if (ids.size >= QUERY_TOTAL_CAP) return;
      edges.push(edge);
      if (!ids.has(edge.to)) { ids.add(edge.to); queue.push(edge.to); }
    });
  }
  return { nodeIds: ids, edges: edges, capped: qi < queue.length };
}

var PREMADE_QUERIES = [
  { id: 'domain-admins', label: 'Find all Domain Admins', run: function () {
    var seeds = findGroupsByPrefix('DOMAIN ADMINS@');
    if (!seeds.length) return null;
    var r = expandSeedSet(seeds);
    return { nodeIds: r.nodeIds, edges: r.edges, pinnedIds: new Set(seeds),
      caption: 'Domain Admins and direct relationships' + (r.capped ? ' (truncated)' : '') };
  }},
  { id: 'domain-controllers', label: 'Find all Domain Controllers', run: function () {
    var seeds = findGroupsByPrefix('DOMAIN CONTROLLERS@');
    if (!seeds.length) return null;
    var r = expandSeedSet(seeds);
    return { nodeIds: r.nodeIds, edges: r.edges, pinnedIds: new Set(seeds),
      caption: 'Domain Controllers group and members' + (r.capped ? ' (truncated)' : '') };
  }},
  { id: 'kerberoastable', label: 'Find Kerberoastable Users', run: function () {
    var ids = [];
    graph.nodes.forEach(function (n) { if (n.kind === 'User' && propertyValue(n, ['hasspn']) === true) ids.push(n.id); });
    if (!ids.length) return null;
    return flatFilterResult(ids, 'Kerberoastable users (SPN set)');
  }},
  { id: 'unconstrained-delegation', label: 'Find Unconstrained Delegation', run: function () {
    var ids = [];
    graph.nodes.forEach(function (n) {
      if ((n.kind === 'Computer' || n.kind === 'User') && propertyValue(n, ['unconstraineddelegation']) === true) ids.push(n.id);
    });
    if (!ids.length) return null;
    return flatFilterResult(ids, 'Principals with unconstrained delegation');
  }},
  { id: 'high-value', label: 'Find High Value Targets', run: function () {
    var ids = [];
    graph.nodes.forEach(function (n) { if (n.highValue) ids.push(n.id); });
    if (!ids.length) return null;
    var r = expandSeedSet(ids, 5);
    return { nodeIds: r.nodeIds, edges: r.edges, pinnedIds: new Set(ids),
      caption: 'High value targets and their closest relationships' + (r.capped ? ' (truncated)' : '') };
  }},
  { id: 'dcsync', label: 'Find DCSync Rights', run: function () {
    var permissionGroups = new Map();
    graph.edges.forEach(function (e) {
      var kind = String(e.kind || '').toLowerCase();
      if (kind !== 'getchanges' && kind !== 'getchangesall' && kind !== 'dcsync') return;
      var key = JSON.stringify([String(e.from), String(e.to)]);
      if (!permissionGroups.has(key)) permissionGroups.set(key, { edges: [], getChanges: false, getChangesAll: false, direct: false });
      var group = permissionGroups.get(key);
      group.edges.push(e);
      if (kind === 'getchanges') group.getChanges = true;
      else if (kind === 'getchangesall') group.getChangesAll = true;
      else group.direct = true;
    });
    var edges = [];
    permissionGroups.forEach(function (group) {
      if (group.direct || (group.getChanges && group.getChangesAll)) edges = edges.concat(group.edges);
    });
    if (!edges.length) return null;
    var nodeIds = new Set();
    edges.forEach(function (e) { nodeIds.add(e.from); nodeIds.add(e.to); });
    return { nodeIds: nodeIds, edges: edges, pinnedIds: nodeIds, caption: 'Principals with complete DCSync rights' };
  }},
  { id: 'trusts', label: 'Map Domain Trusts', run: function () {
    var edges = graph.edges.filter(function (e) { return /^(Trust|TrustedBy|SameForestTrust|CrossForestTrust)$/i.test(e.kind); });
    if (!edges.length) return null;
    var nodeIds = new Set();
    edges.forEach(function (e) { nodeIds.add(e.from); nodeIds.add(e.to); });
    return { nodeIds: nodeIds, edges: edges, pinnedIds: nodeIds, caption: 'Domain trust relationships' };
  }},
  { id: 'adcs-overview', label: 'AD CS — PKI Overview', run: adcsOverviewResult },
  { id: 'adcs-escalations', label: 'AD CS — Computed ESC Paths', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) { return /^ADCSESC(?:[1-9]|1[0-5])[A-Z]?$/i.test(String(edge.kind || '')); }),
      'BloodHound-computed AD CS escalation paths');
  }},
  { id: 'adcs-esc1', label: 'AD CS — Potential ESC1', run: potentialESC1Result },
  { id: 'adcs-esc3', label: 'AD CS — Enrollment Agent Paths', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) {
      return /^(DelegatedEnrollmentAgent|EnrollOnBehalfOf|ADCSESC3)$/i.test(String(edge.kind || ''));
    }), 'AD CS enrollment-agent paths (ESC3)');
  }},
  { id: 'adcs-esc4', label: 'AD CS — Template Control (ESC4)', run: function () {
    return adcsControlResult('CertTemplate',
      /^(GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|WritePKINameFlag|WritePKIEnrollmentFlag|ADCSESC4)$/i,
      'Certificate template control paths (ESC4 prerequisites)');
  }},
  { id: 'adcs-ca-control', label: 'AD CS — CA Control / GoldenCert', run: function () {
    return adcsControlResult('EnterpriseCA',
      /^(ManageCA|ManageCertificates|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|GoldenCert|ADCSESC5|ADCSESC6|ADCSESC7)$/i,
      'Enterprise CA control paths (ESC5/6/7 and Golden Certificate prerequisites)');
  }},
  { id: 'adcs-relay', label: 'AD CS — Relay Paths (ESC8/11)', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) {
      return /^(ADCSESC8|ADCSESC11|CoerceAndRelayNTLMToADCS|CoerceAndRelayNTLMToHTTPSCA|CoerceAndRelayNTLMToHTTPCA)$/i.test(String(edge.kind || ''));
    }), 'AD CS NTLM relay paths (ESC8/11)');
  }},
  { id: 'paths-to-da', label: 'Shortest Paths to Domain Admins', run: function () {
    var targets = expandGroupMembers(findGroupsByPrefix('DOMAIN ADMINS@'));
    if (!targets.length) return null;
    var bfs = reverseBFSFromTargets(targets, true);
    var r = extractPathsToTargets(bfs.dist, bfs.parent, null, QUERY_TOTAL_CAP);
    if (!r.nodeIds.size) return { empty: true, caption: 'No paths found to Domain Admins in the loaded data.' };
    return { nodeIds: r.nodeIds, edges: r.edges, pinnedIds: new Set(targets),
      caption: 'Shortest paths to Domain Admins' + (r.capped ? ' (shortest ' + r.nodeIds.size + ' nodes shown, truncated)' : '') };
  }},
  { id: 'paths-to-hvt', label: 'Shortest Paths to High Value Targets', run: function () {
    var targets = []; graph.nodes.forEach(function (n) { if (n.highValue) targets.push(n.id); });
    if (!targets.length) return null;
    var bfs = reverseBFSFromTargets(targets, true);
    var r = extractPathsToTargets(bfs.dist, bfs.parent, null, QUERY_TOTAL_CAP);
    if (!r.nodeIds.size) return { empty: true, caption: 'No paths found to high value targets in the loaded data.' };
    return { nodeIds: r.nodeIds, edges: r.edges, pinnedIds: new Set(targets),
      caption: 'Shortest paths to high value targets' + (r.capped ? ' (truncated)' : '') };
  }},
  { id: 'kerb-to-da', label: 'Kerberoastable Users \u2192 Domain Admins', run: function () {
    var sources = []; graph.nodes.forEach(function (n) { if (n.kind === 'User' && propertyValue(n, ['hasspn']) === true) sources.push(n.id); });
    var targets = expandGroupMembers(findGroupsByPrefix('DOMAIN ADMINS@'));
    if (!sources.length || !targets.length) return null;
    var bfs = reverseBFSFromTargets(targets, true);
    var r = extractPathsToTargets(bfs.dist, bfs.parent, sources, QUERY_TOTAL_CAP);
    if (!r.nodeIds.size) return { empty: true, caption: 'No paths found from kerberoastable users to Domain Admins.' };
    var pinned = new Set(targets); sources.forEach(function (s) { pinned.add(s); });
    return { nodeIds: r.nodeIds, edges: r.edges, pinnedIds: pinned,
      caption: 'Paths from kerberoastable users to Domain Admins' + (r.capped ? ' (truncated)' : '') };
  }}
];

// Research-informed lab workflows that are useful with the fields and edge
// types emitted by the supported BloodHound collectors. Queries return null
// when the relevant collection data is absent, rather than guessing.
PREMADE_QUERIES = PREMADE_QUERIES.concat([
  { id: 'owned-to-da', label: 'Owned Objects → Domain Admins', category: 'Attack paths', run: function () {
    return pathResult(Array.from(ownedNodeIds), expandGroupMembers(findGroupsByPrefix('DOMAIN ADMINS@')),
      'Shortest paths from owned objects to Domain Admins');
  }},
  { id: 'owned-to-hvt', label: 'Owned Objects → High Value Targets', category: 'Attack paths', run: function () {
    return pathResult(Array.from(ownedNodeIds), highValueIds(), 'Shortest paths from owned objects to high value targets');
  }},
  { id: 'easiest-owned-to-hvt', label: 'Lowest-Cost Owned → High Value Paths', category: 'Attack paths', run: function () {
    return weightedPathResult(Array.from(ownedNodeIds), highValueIds(),
      'Lowest-cost paths from owned objects to high value targets');
  }},
  { id: 'low-priv-to-hvt', label: 'Low-Privilege Groups → High Value Targets', category: 'Attack paths', run: function () {
    var groups = [];
    ['DOMAIN USERS@', 'AUTHENTICATED USERS@', 'EVERYONE@', 'DOMAIN COMPUTERS@'].forEach(function (name) {
      groups = groups.concat(findGroupsByPrefix(name));
    });
    return pathResult(groups, highValueIds(), 'Paths from broad low-privilege groups to high value targets');
  }},
  { id: 'paths-to-privileged-groups', label: 'Paths to Other Privileged Groups', category: 'Attack paths', run: function () {
    var targets = groupIdsByRids(['518', '519', '544', '548', '549', '550', '551', '552']);
    if (!targets.length) return null;
    var bfs = reverseBFSFromTargets(targets, true);
    var result = extractPathsToTargets(bfs.dist, bfs.parent, null, QUERY_TOTAL_CAP);
    return result.edges.length ? { nodeIds: result.nodeIds, edges: result.edges, pinnedIds: new Set(targets),
      caption: 'Shortest paths to privileged groups other than Domain Admins' + (result.capped ? ' (truncated)' : '') } : null;
  }},
  { id: 'attack-path-chokepoints', label: 'Attack Path Choke Points', category: 'Attack paths', run: function () {
    var targets = highValueIds();
    if (!targets.length) return null;
    var bfs = reverseBFSFromTargets(targets, true), score = new Map();
    bfs.dist.forEach(function (distance, source) {
      if (!distance || targets.indexOf(source) !== -1) return;
      var current = source, hops = 0;
      while (bfs.parent.has(current) && hops++ < 100) {
        current = bfs.parent.get(current).next;
        if (targets.indexOf(current) === -1) score.set(current, (score.get(current) || 0) + 1);
      }
    });
    var chokeIds = Array.from(score.keys()).sort(function (a, b) { return score.get(b) - score.get(a); }).slice(0, 20);
    if (!chokeIds.length) return null;
    var result = extractPathsToTargets(bfs.dist, bfs.parent, chokeIds, QUERY_TOTAL_CAP);
    return { nodeIds: result.nodeIds, edges: result.edges, pinnedIds: new Set(chokeIds),
      caption: 'Top attack-path choke points ranked by reachable paths to high value targets' };
  }},
  { id: 'asrep-roastable', label: 'Find AS-REP Roastable Users', category: 'Credentials', run: function () {
    var ids = [];
    graph.nodes.forEach(function (node) {
      if (node.kind === 'User' && isEnabledNode(node) && propertyValue(node, ['dontreqpreauth']) === true) ids.push(node.id);
    });
    return ids.length ? flatFilterResult(ids, 'Enabled users that do not require Kerberos pre-authentication') : null;
  }},
  { id: 'laps-readers', label: 'Find LAPS Password Readers', category: 'Credentials', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) { return /^ReadLAPSPassword$/i.test(edge.kind); }),
      'Principals able to read LAPS-managed local administrator passwords');
  }},
  { id: 'gmsa-readers', label: 'Find gMSA Password Readers', category: 'Credentials', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) { return /^ReadGMSAPassword$/i.test(edge.kind); }),
      'Principals able to read group managed service account passwords');
  }},
  { id: 'old-active-passwords', label: 'Active Users with Old Passwords', category: 'Credentials', run: function () {
    var cutoff = Math.floor(Date.now() / 1000) - 365 * 86400, ids = [];
    graph.nodes.forEach(function (node) {
      var changed = timestampSeconds(propertyValue(node, ['pwdlastset', 'passwordlastset']));
      if (node.kind === 'User' && isEnabledNode(node) && changed && changed < cutoff) ids.push(node.id);
    });
    return ids.length ? flatFilterResult(ids, 'Enabled users whose password was last set more than one year ago') : null;
  }},
  { id: 'dangerous-direct-rights', label: 'Dangerous Direct Rights', category: 'Object control', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) {
      var source = graph.nodes.get(edge.from);
      return !edge.inherited && source && (source.kind === 'User' || source.kind === 'Computer') && DANGEROUS_RIGHTS.test(edge.kind);
    }), 'Dangerous direct object-control rights held by users or computers');
  }},
  { id: 'dangerous-broad-group-rights', label: 'Dangerous Rights held by Broad Groups', category: 'Object control', run: function () {
    var broad = new Set();
    ['DOMAIN USERS@', 'AUTHENTICATED USERS@', 'EVERYONE@', 'DOMAIN COMPUTERS@'].forEach(function (name) {
      findGroupsByPrefix(name).forEach(function (id) { broad.add(id); });
    });
    return resultFromEdges(graph.edges.filter(function (edge) { return broad.has(edge.from) && DANGEROUS_RIGHTS.test(edge.kind); }),
      'Dangerous object-control rights granted to broad groups');
  }},
  { id: 'lateral-movement', label: 'Lateral Movement Access', category: 'Sessions & lateral movement', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) { return LATERAL_RIGHTS.test(edge.kind); }),
      'Remote administration and lateral-movement relationships');
  }},
  { id: 'computer-admin-to-computer', label: 'Computers Admin to Other Computers', category: 'Sessions & lateral movement', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) {
      var source = graph.nodes.get(edge.from), target = graph.nodes.get(edge.to);
      return /^AdminTo$/i.test(edge.kind) && source && target && source.kind === 'Computer' && target.kind === 'Computer';
    }), 'Computer accounts with local administrator rights on other computers');
  }},
  { id: 'logged-on-privileged-users', label: 'Logged-On Privileged Users', category: 'Sessions & lateral movement', run: function () {
    var privileged = privilegedPrincipalIds();
    return edgesWithMembershipContext(graph.edges.filter(function (edge) {
      return edge.kind === 'HasSession' && privileged.has(edge.to);
    }), privileged, 'Computers with sessions for privileged users');
  }},
  { id: 'privileged-sessions-nondc', label: 'Privileged Sessions on Non-DCs', category: 'Sessions & lateral movement', run: function () {
    var privileged = privilegedPrincipalIds();
    return resultFromEdges(graph.edges.filter(function (edge) {
      var computer = graph.nodes.get(edge.from);
      return edge.kind === 'HasSession' && privileged.has(edge.to) && computer &&
        propertyValue(computer, ['isdc']) !== true && !/DOMAIN CONTROLLER/i.test(String(propertyValue(computer, ['description']) || ''));
    }), 'Privileged user sessions on computers not identified as domain controllers');
  }},
  { id: 'constrained-delegation', label: 'Constrained Delegation', category: 'Delegation', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) { return /^AllowedToDelegate$/i.test(edge.kind); }),
      'Principals configured for constrained delegation');
  }},
  { id: 'rbcd', label: 'Resource-Based Constrained Delegation', category: 'Delegation', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) { return /^AllowedToAct$/i.test(edge.kind); }),
      'Resource-based constrained delegation relationships');
  }},
  { id: 'privileged-sessions-unconstrained', label: 'Privileged Sessions on Unconstrained Hosts', category: 'Delegation', run: function () {
    var privileged = privilegedPrincipalIds();
    return resultFromEdges(graph.edges.filter(function (edge) {
      var host = graph.nodes.get(edge.from);
      return edge.kind === 'HasSession' && privileged.has(edge.to) && host &&
        propertyValue(host, ['unconstraineddelegation']) === true;
    }), 'Privileged sessions exposed on unconstrained-delegation hosts');
  }},
  { id: 'sid-history', label: 'SID History Relationships', category: 'Identity hygiene', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) { return /^HasSIDHistory$/i.test(edge.kind); }),
      'Objects with SID history relationships');
  }},
  { id: 'highvalue-outside-protected-users', label: 'High-Value Users outside Protected Users', category: 'Identity hygiene', run: function () {
    var protectedGroups = findGroupsByPrefix('PROTECTED USERS@');
    if (!protectedGroups.length) return null;
    var protectedIds = nestedMembers(protectedGroups), privileged = privilegedPrincipalIds(), ids = [];
    privileged.forEach(function (id) {
      var node = graph.nodes.get(id);
      if (node && node.kind === 'User' && !protectedIds.has(node.id)) ids.push(node.id);
    });
    return ids.length ? flatFilterResult(ids, 'High-value users that are not members of Protected Users') : null;
  }},
  { id: 'inactive-privileged-accounts', label: 'Enabled Inactive Privileged Accounts', category: 'Identity hygiene', run: function () {
    var privileged = privilegedPrincipalIds(), cutoff = Math.floor(Date.now() / 1000) - 90 * 86400, ids = [];
    privileged.forEach(function (id) {
      var node = graph.nodes.get(id), raw = propertyValue(node, ['lastlogontimestamp', 'lastlogon']), last = timestampSeconds(raw);
      if (node && (node.kind === 'User' || node.kind === 'Computer') && isEnabledNode(node) && raw != null && (!last || last < cutoff)) ids.push(id);
    });
    return ids.length ? flatFilterResult(ids, 'Enabled privileged accounts with no recorded logon in 90 days') : null;
  }},
  { id: 'unsupported-active-computers', label: 'Unsupported Active Computers with Incoming Access', category: 'Identity hygiene', run: function () {
    var unsupported = new Set();
    graph.nodes.forEach(function (node) {
      var os = String(propertyValue(node, ['operatingsystem']) || '');
      if (node.kind === 'Computer' && isEnabledNode(node) && /(Windows (XP|Vista|7|8(?!\.1)|Server 2003|Server 2008|Server 2012))/i.test(os)) unsupported.add(node.id);
    });
    return resultFromEdges(graph.edges.filter(function (edge) {
      return unsupported.has(edge.to) && (LATERAL_RIGHTS.test(edge.kind) || DANGEROUS_RIGHTS.test(edge.kind));
    }), 'Incoming access paths to active computers running legacy Windows versions');
  }},
  { id: 'writable-gpo-impact', label: 'Writable GPOs and Affected Objects', category: 'Policy & hierarchy', run: function () {
    var control = graph.edges.filter(function (edge) {
      var target = graph.nodes.get(edge.to);
      return target && target.kind === 'GPO' && OBJECT_CONTROL_RIGHTS.test(edge.kind);
    }), evidence = control.slice(), linkedContainers = [];
    var controlled = new Set(control.map(function (edge) { return edge.to; }));
    graph.edges.forEach(function (edge) {
      if (edge.kind === 'GPLink' && controlled.has(edge.from)) { evidence.push(edge); linkedContainers.push(edge.to); }
    });
    var closure = containmentClosure(linkedContainers);
    evidence = evidence.concat(closure.edges);
    return resultFromEdges(evidence, 'Writable GPOs, their links, and contained affected objects');
  }},
  { id: 'writable-container-impact', label: 'Writable OUs/Containers and Descendants', category: 'Policy & hierarchy', run: function () {
    var control = graph.edges.filter(function (edge) {
      var target = graph.nodes.get(edge.to);
      return target && (target.kind === 'OU' || target.kind === 'Container') && OBJECT_CONTROL_RIGHTS.test(edge.kind);
    }), evidence = control.slice();
    var closure = containmentClosure(control.map(function (edge) { return edge.to; }));
    return resultFromEdges(evidence.concat(closure.edges), 'Writable OUs/containers and their descendant objects');
  }},
  { id: 'deep-group-nesting', label: 'Deep Group Nesting', category: 'Policy & hierarchy', run: function () {
    var evidence = [], seen = new Set(), expansions = 0;
    graph.nodes.forEach(function (start) {
      if (start.kind !== 'Group') return;
      var queue = [{ id: start.id, path: [] }], qi = 0;
      while (qi < queue.length && expansions++ < 50000) {
        var state = queue[qi++];
        if (state.path.length >= 3) state.path.forEach(function (edge) {
          var key = edgeIdentityKey(edge.from, edge.to, edge.kind);
          if (!seen.has(key)) { seen.add(key); evidence.push(edge); }
        });
        if (state.path.length >= 8) continue;
        outgoingEdges(state.id).forEach(function (edge) {
          if (edge.kind === 'MemberOf' && edge.from === state.id && graph.nodes.get(edge.to) && graph.nodes.get(edge.to).kind === 'Group') {
            queue.push({ id: edge.to, path: state.path.concat([edge]) });
          }
        });
      }
    });
    return resultFromEdges(evidence, 'Group membership chains at least three levels deep');
  }},
  { id: 'circular-group-nesting', label: 'Circular Group Nesting', category: 'Policy & hierarchy', run: function () {
    var evidence = [], components = [], adjacency = new Map(), reverse = new Map();
    var groups = getGraphIndex().nodesByKind.get('Group') || [];
    groups.forEach(function (id) { outgoingEdges(id).forEach(function (edge) {
      var target = graph.nodes.get(edge.to);
      if (edge.kind !== 'MemberOf' || !target || target.kind !== 'Group') return;
      indexPush(adjacency, id, edge.to); indexPush(reverse, edge.to, id);
    }); });
    var visited = new Set(), order = [];
    groups.forEach(function (start) {
      if (visited.has(start)) return;
      var work = [{ id: start, done: false }];
      while (work.length) {
        var state = work.pop();
        if (state.done) { order.push(state.id); continue; }
        if (visited.has(state.id)) continue;
        visited.add(state.id); work.push({ id: state.id, done: true });
        (adjacency.get(state.id) || []).forEach(function (id) {
          if (!visited.has(id)) work.push({ id: id, done: false });
        });
      }
    });
    visited.clear();
    while (order.length) {
      var root = order.pop();
      if (visited.has(root)) continue;
      var component = [], stack = [root]; visited.add(root);
      while (stack.length) {
        var id = stack.pop(); component.push(id);
        (reverse.get(id) || []).forEach(function (previous) {
          if (!visited.has(previous)) { visited.add(previous); stack.push(previous); }
        });
      }
      components.push(component);
    }
    components.forEach(function (component) {
      var ids = new Set(component);
      component.forEach(function (id) { outgoingEdges(id).forEach(function (edge) {
        if (edge.kind === 'MemberOf' && ids.has(edge.to) && (component.length > 1 || edge.from === edge.to)) evidence.push(edge);
      }); });
    });
    return resultFromEdges(evidence, 'Circular nested-group membership relationships');
  }},
  { id: 'cross-domain-membership', label: 'Cross-Domain Group Membership', category: 'Domains & trusts', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) {
      if (edge.kind !== 'MemberOf') return false;
      var left = nodeDomain(graph.nodes.get(edge.from)), right = nodeDomain(graph.nodes.get(edge.to));
      return left && right && left !== right;
    }), 'Group memberships whose member and group belong to different domains');
  }},
  { id: 'cross-domain-acls', label: 'ACLs Crossing Domains', category: 'Domains & trusts', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) {
      if (!DANGEROUS_RIGHTS.test(edge.kind) && !/^GetChanges(All)?$/i.test(edge.kind)) return false;
      var left = nodeDomain(graph.nodes.get(edge.from)), right = nodeDomain(graph.nodes.get(edge.to));
      return left && right && left !== right;
    }), 'Object-control rights crossing domain boundaries');
  }},
  { id: 'same-forest-trust-paths', label: 'Same-Forest Trust Relationships', category: 'Domains & trusts', run: function () {
    return resultFromEdges(graph.edges.filter(function (edge) { return /^SameForestTrust$/i.test(edge.kind); }),
      'Same-forest domain trust relationships');
  }}
]);

var QUERY_CATEGORY_ORDER = [
  'Attack paths', 'Credentials', 'Object control', 'Sessions & lateral movement',
  'Delegation', 'Identity hygiene', 'Policy & hierarchy', 'Domains & trusts', 'AD CS'
];
var QUERY_CATEGORY_BY_ID = {
  'paths-to-da': 'Attack paths', 'paths-to-hvt': 'Attack paths', 'kerb-to-da': 'Attack paths',
  'kerberoastable': 'Credentials', 'dcsync': 'Object control',
  'unconstrained-delegation': 'Delegation', 'trusts': 'Domains & trusts',
  'domain-admins': 'Identity hygiene', 'domain-controllers': 'Identity hygiene', 'high-value': 'Identity hygiene',
  'adcs-overview': 'AD CS', 'adcs-escalations': 'AD CS', 'adcs-esc1': 'AD CS',
  'adcs-esc3': 'AD CS', 'adcs-esc4': 'AD CS', 'adcs-ca-control': 'AD CS', 'adcs-relay': 'AD CS'
};

var QUERY_DETAILS = {
  'domain-admins': {
    description: 'Shows the Domain Admins groups, their direct members, and nearby relationships.',
    use: 'Use it to establish the primary domain-level privilege boundary and inspect who currently belongs to it.',
    requires: 'Group and group-membership collection.'
  },
  'domain-controllers': {
    description: 'Shows Domain Controllers groups, their computer members, and nearby relationships.',
    use: 'Use it to identify authentication infrastructure and relationships touching domain controllers.',
    requires: 'Group, computer, and group-membership collection.'
  },
  'kerberoastable': {
    description: 'Finds user accounts with a service principal name (SPN).',
    use: 'These accounts may expose a service ticket hash for offline password auditing.',
    requires: 'User properties, including the SPN indicator.'
  },
  'unconstrained-delegation': {
    description: 'Finds users and computers configured for unconstrained Kerberos delegation.',
    use: 'Privileged authentication reaching these principals can expose reusable Kerberos credentials.',
    requires: 'User and computer delegation properties.'
  },
  'high-value': {
    description: 'Shows objects marked high value by BloodHound and their closest relationships.',
    use: 'Use it as a quick inventory of the assets and identities that deserve priority during path analysis.',
    requires: 'Collected objects with high-value classification.'
  },
  'dcsync': {
    description: 'Finds principals with DCSync or the complete GetChanges and GetChangesAll permission pair.',
    use: 'These rights can permit replication of sensitive directory credential material.',
    requires: 'ACL collection against domain objects.'
  },
  'trusts': {
    description: 'Maps collected trust relationships between domains.',
    use: 'Use it to understand authentication boundaries and possible cross-domain attack-path scope.',
    requires: 'Domain trust collection.'
  },
  'adcs-overview': {
    description: 'Shows collected certificate authorities, templates, policy objects, and PKI relationships.',
    use: 'Use it to orient AD CS review before investigating specific escalation conditions.',
    requires: 'AD CS collection.'
  },
  'adcs-escalations': {
    description: 'Shows AD CS escalation relationships already computed by BloodHound.',
    use: 'Use it to review collector-supported ESC findings without manually reconstructing each path.',
    requires: 'AD CS data containing computed ADCSESC relationships.'
  },
  'adcs-esc1': {
    description: 'Finds published authentication templates that permit enrollee-supplied subjects without approval or signatures.',
    use: 'Combined with an enrollment right, these settings can indicate an ESC1-style certificate path.',
    requires: 'Certificate-template properties, enrollment ACLs, and CA publication relationships.'
  },
  'adcs-esc3': {
    description: 'Shows enrollment-agent and enroll-on-behalf-of certificate relationships.',
    use: 'Use it to identify principals that may request certificates on behalf of another identity.',
    requires: 'AD CS enrollment-agent relationship collection.'
  },
  'adcs-esc4': {
    description: 'Finds principals that can modify or take control of certificate templates.',
    use: 'Template control may allow an otherwise safe template to be changed into an exploitable configuration.',
    requires: 'Certificate-template ACL collection.'
  },
  'adcs-ca-control': {
    description: 'Finds principals with administrative or ownership rights over enterprise certificate authorities.',
    use: 'CA-level control can affect certificate issuance policy and may enable high-impact PKI abuse.',
    requires: 'Enterprise CA security and ACL collection.'
  },
  'adcs-relay': {
    description: 'Shows collected AD CS HTTP or HTTPS NTLM relay paths.',
    use: 'Use it to identify certificate-service endpoints participating in computed ESC8 or ESC11 paths.',
    requires: 'AD CS endpoint and relay-path collection.'
  },
  'paths-to-da': {
    description: 'Calculates shortest directed relationship paths to Domain Admins.',
    use: 'Use it to see the most direct privilege-escalation routes present anywhere in the loaded graph.',
    requires: 'Group membership plus ACL, session, delegation, or access relationships.'
  },
  'paths-to-hvt': {
    description: 'Calculates shortest directed paths to every object marked high value.',
    use: 'This broadens path analysis beyond Domain Admins to other sensitive identities and systems.',
    requires: 'High-value classification and collected relationship data.'
  },
  'kerb-to-da': {
    description: 'Finds directed paths from Kerberoastable users to Domain Admins.',
    use: 'Use it to prioritize service accounts whose compromise would provide further privilege escalation.',
    requires: 'User SPN properties, group membership, and attack-path relationships.'
  },
  'owned-to-da': {
    description: 'Calculates shortest paths from objects marked Owned to Domain Admins.',
    use: 'Use it to model escalation options from the access already obtained in the lab.',
    requires: 'At least one Owned object and collected attack-path relationships.'
  },
  'owned-to-hvt': {
    description: 'Calculates shortest paths from Owned objects to all high-value targets.',
    use: 'Use it to find escalation opportunities that do not necessarily terminate at Domain Admins.',
    requires: 'At least one Owned object, high-value targets, and relationship collection.'
  },
  'easiest-owned-to-hvt': {
    description: 'Ranks paths from Owned objects to high-value targets using heuristic relationship costs.',
    use: 'Lower-cost edges are favored to surface routes that may be simpler to exercise in a lab.',
    requires: 'Owned objects, high-value targets, and relationship collection. Costs are heuristic, not risk scores.'
  },
  'low-priv-to-hvt': {
    description: 'Finds paths from broad groups such as Domain Users or Authenticated Users to high-value targets.',
    use: 'Use it to locate escalation routes potentially available to a typical low-privilege principal.',
    requires: 'Broad built-in groups and collected attack-path relationships.'
  },
  'paths-to-privileged-groups': {
    description: 'Calculates paths to privileged built-in groups other than Domain Admins.',
    use: 'Use it to uncover escalation routes through operators, administrators, and forest-level groups.',
    requires: 'Group membership and attack-path relationship collection.'
  },
  'attack-path-chokepoints': {
    description: 'Ranks intermediate objects that repeatedly occur on shortest paths to high-value targets.',
    use: 'Use it to identify shared control points whose compromise or remediation affects many routes.',
    requires: 'High-value targets and sufficiently connected relationship data.'
  },
  'asrep-roastable': {
    description: 'Finds enabled users that do not require Kerberos pre-authentication.',
    use: 'These accounts may allow an offline password audit without first possessing domain credentials.',
    requires: 'User properties including enabled and dontreqpreauth.'
  },
  'laps-readers': {
    description: 'Finds principals permitted to read LAPS-managed local administrator passwords.',
    use: 'Use it to identify identities that can obtain privileged credentials for managed endpoints.',
    requires: 'ACL collection that emits ReadLAPSPassword relationships.'
  },
  'gmsa-readers': {
    description: 'Finds principals permitted to read group managed service account passwords.',
    use: 'Use it to determine who can retrieve credentials associated with gMSA identities.',
    requires: 'ACL collection that emits ReadGMSAPassword relationships.'
  },
  'old-active-passwords': {
    description: 'Finds enabled users whose recorded password-set time is more than one year old.',
    use: 'Use it to prioritize password-policy review; age alone does not prove that a password is weak.',
    requires: 'User enabled and pwdlastset or passwordlastset properties.'
  },
  'dangerous-direct-rights': {
    description: 'Shows non-inherited high-impact object-control rights held directly by users or computers.',
    use: 'Direct assignments can reveal precise escalation opportunities that are easy to miss in group review.',
    requires: 'ACL collection.'
  },
  'dangerous-broad-group-rights': {
    description: 'Finds high-impact rights assigned to broad groups such as Domain Users or Everyone.',
    use: 'Use it to locate permissions that may expose an object to a large low-privilege population.',
    requires: 'ACL and group collection.'
  },
  'lateral-movement': {
    description: 'Shows AdminTo, RDP, PowerShell remoting, and DCOM access relationships.',
    use: 'Use it to map possible movement between the current set of principals and computers.',
    requires: 'Local group and session-style computer collection.'
  },
  'computer-admin-to-computer': {
    description: 'Finds computer accounts with local administrator rights on other computers.',
    use: 'These relationships can expose machine-account-based lateral movement or tiering weaknesses.',
    requires: 'Computer and local administrator collection.'
  },
  'logged-on-privileged-users': {
    description: 'Shows computers with collected sessions belonging to privileged users.',
    use: 'Use it to locate hosts where privileged credentials or tokens may be exposed.',
    requires: 'Session and nested group-membership collection.'
  },
  'privileged-sessions-nondc': {
    description: 'Shows privileged user sessions on computers not identified as domain controllers.',
    use: 'Use it to find workstation or member-server exposure created by privileged interactive use.',
    requires: 'Session, computer-property, and group-membership collection.'
  },
  'constrained-delegation': {
    description: 'Shows principals configured to delegate Kerberos authentication to specific services or computers.',
    use: 'Use it to understand constrained-delegation paths and the systems they can reach.',
    requires: 'Delegation collection that emits AllowedToDelegate relationships.'
  },
  'rbcd': {
    description: 'Shows resource-based constrained delegation relationships.',
    use: 'Use it to identify principals allowed to act on behalf of users against a target computer.',
    requires: 'ACL/delegation collection that emits AllowedToAct relationships.'
  },
  'privileged-sessions-unconstrained': {
    description: 'Finds privileged sessions present on hosts configured for unconstrained delegation.',
    use: 'This combination highlights hosts where sensitive Kerberos authentication may be exposed.',
    requires: 'Session, delegation-property, and group-membership collection.'
  },
  'sid-history': {
    description: 'Shows current identities connected to historical SIDs.',
    use: 'Use it to review migration remnants and determine whether historical privileges remain effective.',
    requires: 'SID history collection.'
  },
  'highvalue-outside-protected-users': {
    description: 'Finds privileged users that are not members of the Protected Users group.',
    use: 'Use it to review whether sensitive accounts receive the group’s additional authentication protections.',
    requires: 'Protected Users, privileged groups, and nested membership collection.'
  },
  'inactive-privileged-accounts': {
    description: 'Finds enabled privileged accounts with a recorded logon older than 90 days or equal to zero.',
    use: 'Use it to locate stale privileged identities that may no longer have an operational owner.',
    requires: 'Account enabled/logon properties and nested group membership.'
  },
  'unsupported-active-computers': {
    description: 'Finds enabled legacy Windows systems that have incoming administrative or control relationships.',
    use: 'Use it to prioritize older endpoints that are both exposed and reachable through collected access paths.',
    requires: 'Computer operating-system properties plus ACL or local-access collection.'
  },
  'writable-gpo-impact': {
    description: 'Connects writable GPOs to their linked containers and collected descendant objects.',
    use: 'Use it to estimate which identities or computers could be affected by control of a policy object.',
    requires: 'GPO ACLs, GPLink relationships, and OU/container hierarchy collection.'
  },
  'writable-container-impact': {
    description: 'Connects writable OUs or containers to their collected descendants.',
    use: 'Use it to understand the downstream scope of control over an organizational hierarchy.',
    requires: 'OU/container ACL and containment collection.'
  },
  'deep-group-nesting': {
    description: 'Finds group membership chains that are at least three groups deep.',
    use: 'Use it to expose indirect privilege that is difficult to recognize from direct membership alone.',
    requires: 'Group and nested membership collection.'
  },
  'circular-group-nesting': {
    description: 'Finds nested group membership paths that loop back to their starting group.',
    use: 'Use it to identify confusing or unintended membership structures that complicate privilege review.',
    requires: 'Group and nested membership collection.'
  },
  'cross-domain-membership': {
    description: 'Shows group memberships where the member and destination group belong to different domains.',
    use: 'Use it to identify privilege flowing across domain boundaries through group nesting.',
    requires: 'Multi-domain object and group-membership collection.'
  },
  'cross-domain-acls': {
    description: 'Shows high-impact object-control rights whose source and target belong to different domains.',
    use: 'Use it to locate permissions that create control paths across domain boundaries.',
    requires: 'Multi-domain object and ACL collection.'
  },
  'same-forest-trust-paths': {
    description: 'Shows trust relationships classified as remaining within the same forest.',
    use: 'Use it to understand intra-forest domain connectivity before reviewing cross-domain privilege paths.',
    requires: 'Domain trust collection with trust-type metadata.'
  }
};

PREMADE_QUERIES.forEach(function (query) {
  var details = QUERY_DETAILS[query.id];
  if (!details) return;
  query.description = details.description;
  query.use = details.use;
  query.requires = details.requires;
});

function renderQueryList() {
  var el = byId('queryList');
  var selectedQueryId = el.value;
  var grouped = new Map();
  PREMADE_QUERIES.forEach(function (query) {
    var category = query.category || QUERY_CATEGORY_BY_ID[query.id] || 'Other';
    if (!grouped.has(category)) grouped.set(category, []);
    grouped.get(category).push(query);
  });
  var categories = QUERY_CATEGORY_ORDER.concat(Array.from(grouped.keys()).filter(function (category) {
    return QUERY_CATEGORY_ORDER.indexOf(category) === -1;
  }));
  el.innerHTML = '<option value="">Select a query…</option>' + categories.map(function (category) {
    var queries = grouped.get(category) || [];
    if (!queries.length) return '';
    return '<optgroup label="' + escapeHtml(category) + '">' + queries.map(function (query) {
      return '<option value="' + query.id + '">' + escapeHtml(query.label) + '</option>';
    }).join('') + '</optgroup>';
  }).join('');
  // Rebuilding the options after another collection is loaded should not
  // erase the user's last saved-query choice.
  if (PREMADE_QUERIES.some(function (query) { return query.id === selectedQueryId; })) {
    el.value = selectedQueryId;
  }
}

function refreshEdgeKindOptions() {
  var kinds = new Set();
  getGraphIndex().allEdges.forEach(function (e) { if (e.kind) kinds.add(e.kind); });
  byId('edgeKindOptions').innerHTML = Array.from(kinds).sort(function (a, b) {
    return a.localeCompare(b);
  }).map(function (kind) { return '<option value="' + escapeHtml(kind) + '"></option>'; }).join('');
  byId('edgeQueryInput').value = '';
  byId('edgeQueryStatus').textContent = graph.edges.length ? 'Search ' + kinds.size + ' available edge values.' : '';
}

function runEdgeQuery(rawValue) {
  var value = rawValue.trim();
  var status = byId('edgeQueryStatus');
  if (!value) {
    status.textContent = graph.edges.length ? 'Enter an edge value to filter the graph.' : '';
    if (graph.nodes.size) {
      if (network) { network.destroy(); network = null; }
      currentView = null;
      byId('workspaceStatus').style.display = 'none';
      setGraphAreaState('ready');
      byId('readyText').textContent = graph.nodes.size.toLocaleString() + ' objects, ' +
        graph.edges.length.toLocaleString() + ' relationships loaded. Choose a query or search for an edge value.';
    }
    return;
  }
  if (!graph.nodes.size) {
    status.textContent = 'Load data before searching edge values.';
    return;
  }

  var needle = value.toLowerCase();
  var exact = byId('edgeMatchMode').value === 'exact';
  var inheritance = byId('edgeInheritance').value;
  var sourceKind = byId('edgeSourceKind').value;
  var targetKind = byId('edgeTargetKind').value;
  var nodeIds = new Set();
  var edges = [];
  var totalMatches = 0;
  var capped = false;
  getGraphIndex().allEdges.forEach(function (e) {
    var edgeKind = String(e.kind || '').toLowerCase();
    if (exact ? edgeKind !== needle : edgeKind.indexOf(needle) === -1) return;
    if (inheritance === 'direct' && e.inherited) return;
    if (inheritance === 'inherited' && !e.inherited) return;
    var source = graph.nodes.get(e.from), target = graph.nodes.get(e.to);
    if (sourceKind && (!source || source.kind !== sourceKind)) return;
    if (targetKind && (!target || target.kind !== targetKind)) return;
    totalMatches++;
    var additions = (nodeIds.has(e.from) ? 0 : 1) + (nodeIds.has(e.to) ? 0 : 1);
    if (nodeIds.size + additions > QUERY_TOTAL_CAP) { capped = true; return; }
    nodeIds.add(e.from);
    nodeIds.add(e.to);
    edges.push(e);
  });

  if (!totalMatches) {
    status.textContent = 'No edge values match “' + value + '”.';
    setGraphAreaState('graph');
    drawGraph(new Set(), [], { caption: 'No edges match “' + value + '”' });
    return;
  }

  status.textContent = totalMatches.toLocaleString() + ' matching relationship' + (totalMatches === 1 ? '' : 's') +
    (capped ? '; graph limited to ' + QUERY_TOTAL_CAP + ' nodes.' : '.');
  setGraphAreaState('graph');
  drawGraph(nodeIds, edges, {
    caption: 'Edges matching “' + value + '” — ' + totalMatches.toLocaleString() + ' relationship' +
      (totalMatches === 1 ? '' : 's') + (capped ? ' (truncated)' : '')
  });
}

// A deliberately small, read-only Cypher-like query engine. It covers the
// common "match nodes/relationships, filter properties, return a subgraph"
// workflow without executing user text as JavaScript.
function customQueryValue(subject, field) {
  if (!subject) return undefined;
  var wanted = field.toLowerCase();
  var direct;
  if (wanted === 'id') direct = subject.id;
  else if (wanted === 'kind') direct = subject.kind;
  else if (wanted === 'name') direct = subject.kind ? displayName(subject) : undefined;
  else if (wanted === 'highvalue') direct = subject.highValue;
  else if (wanted === 'owned') direct = subject.id && typeof ownedNodeIds !== 'undefined' ? ownedNodeIds.has(subject.id) : undefined;
  else if (wanted === 'isstub') direct = subject.isStub;
  else if (wanted === 'category') direct = subject.category;
  else if (wanted === 'inherited') direct = subject.inherited;
  else if (wanted === 'from') direct = subject.from;
  else if (wanted === 'to') direct = subject.to;
  if (direct !== undefined) return direct;
  var props = subject.properties || subject;
  if (Object.prototype.hasOwnProperty.call(props, field)) return props[field];
  for (var key in props) {
    if (Object.prototype.hasOwnProperty.call(props, key) && key.toLowerCase() === wanted) return props[key];
  }
  return undefined;
}

function parseCustomLiteral(raw) {
  raw = raw.trim();
  if ((raw[0] === '"' && raw[raw.length - 1] === '"') || (raw[0] === "'" && raw[raw.length - 1] === "'")) {
    return raw.slice(1, -1).replace(/\\(['"\\])/g, '$1');
  }
  if (/^(true|false)$/i.test(raw)) return raw.toLowerCase() === 'true';
  if (/^null$/i.test(raw)) return null;
  if (/^-?\d+(?:\.\d+)?$/.test(raw)) return Number(raw);
  throw new Error('Values must be quoted strings, numbers, true, false, or null.');
}

function parseCustomOperand(raw) {
  try { return parseCustomLiteral(raw); } catch (_) {}
  var ago = raw.trim().match(/^\(?\s*datetime\(\)\.epochseconds\s*-\s*\(\s*(\d+)\s*\*\s*(\d+)\s*\)\s*\)?$/i);
  if (ago) return Math.floor(Date.now() / 1000) - Number(ago[1]) * Number(ago[2]);
  var list = raw.trim().match(/^\[([\s\S]*)\]$/);
  if (list) return splitCustomOutsideQuotes(list[1], ',').filter(Boolean).map(parseCustomLiteral);
  throw new Error('Unsupported value or expression: ' + raw.trim());
}

function compileCustomRegex(value) {
  var pattern = String(value), flags = '';
  if (pattern.length > 256) throw new Error('Regular expressions are limited to 256 characters.');
  if (/\\[1-9]/.test(pattern) || /\(\?<?[=!]/.test(pattern) || /\([^)]*[+*][^)]*\)\s*[+*{]/.test(pattern)) {
    throw new Error('Regular expression uses a potentially unsafe construct.');
  }
  // Neo4j accepts Java-style inline i/m/s flags at the start of a regex.
  // JavaScript uses constructor flags, so translate the common combinations.
  var inlineFlags = pattern.match(/^\(\?([ims]+)\)/i);
  if (inlineFlags) {
    flags = Array.from(new Set(inlineFlags[1].toLowerCase().split(''))).join('');
    pattern = pattern.slice(inlineFlags[0].length);
  }
  try { return new RegExp(pattern, flags); }
  catch (_) { throw new Error('Invalid regular expression in WHERE.'); }
}

function splitCustomOutsideQuotes(raw, separator) {
  var parts = [], start = 0, quote = null, escaped = false, depth = 0;
  var upper = raw.toUpperCase(), token = separator.toUpperCase();
  for (var i = 0; i < raw.length; i++) {
    var ch = raw[i];
    if (escaped) { escaped = false; continue; }
    if (quote && ch === '\\') { escaped = true; continue; }
    if (ch === '"' || ch === "'") {
      if (!quote) quote = ch; else if (quote === ch) quote = null;
      continue;
    }
    if (quote) continue;
    if (ch === '(' || ch === '[' || ch === '{') { depth++; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth = Math.max(0, depth - 1); continue; }
    var matchesComma = depth === 0 && token === ',' && ch === ',';
    var matchesWord = depth === 0 && token !== ',' && upper.slice(i, i + token.length) === token &&
      (i === 0 || /\s/.test(raw[i - 1])) && (i + token.length === raw.length || /\s/.test(raw[i + token.length]));
    if (matchesComma || matchesWord) {
      parts.push(raw.slice(start, i).trim());
      i += token.length - 1;
      start = i + 1;
    }
  }
  parts.push(raw.slice(start).trim());
  return parts;
}

function compileCustomWhere(raw, aliases) {
  if (!raw) return function () { return true; };
  var groups = splitCustomOutsideQuotes(raw, 'OR').map(function (orPart) {
    return splitCustomOutsideQuotes(orPart, 'AND').map(function (text) {
      var source = text.trim(), negate = false;
      if (/^NOT\s+/i.test(source)) { negate = true; source = source.replace(/^NOT\s+/i, '').trim(); }
      var any = source.match(/^ANY\s*\(\s*([A-Za-z_]\w*)\s+IN\s+([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s+WHERE\s+(?:toUpper\(\s*\1\s*\)|\1)\s+(CONTAINS|STARTS\s+WITH|ENDS\s+WITH|=~)\s+(.+)\)$/i);
      if (any) {
        if (aliases.indexOf(any[2]) === -1) throw new Error('Unknown alias "' + any[2] + '" in WHERE.');
        var anyClause = { any: true, alias: any[2], field: any[3], op: any[4].replace(/\s+/g, ' ').toUpperCase(), expected: parseCustomOperand(any[5]), negate: negate };
        if (anyClause.op === '=~') anyClause.regex = compileCustomRegex(anyClause.expected);
        return anyClause;
      }
      var nullMatch = source.match(/^([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s+IS\s+(NOT\s+)?NULL$/i);
      if (nullMatch) {
        if (aliases.indexOf(nullMatch[1]) === -1) throw new Error('Unknown alias "' + nullMatch[1] + '" in WHERE.');
        return { alias: nullMatch[1], field: nullMatch[2], op: nullMatch[3] ? 'IS NOT NULL' : 'IS NULL', negate: negate };
      }
      var match = source.match(/^([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*(=~|<=|>=|<>|=|!=|<|>|CONTAINS|STARTS\s+WITH|ENDS\s+WITH|IN)\s*(.+)$/i);
      if (!match) {
        var truthy = source.match(/^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/);
        if (!truthy) throw new Error('Could not parse WHERE condition: ' + text.trim());
        match = [truthy[0], truthy[1], truthy[2], '=', 'true'];
      }
      var alias = match[1], field = match[2], op = match[3].replace(/\s+/g, ' ').toUpperCase();
      if (aliases.indexOf(alias) === -1) throw new Error('Unknown alias "' + alias + '" in WHERE.');
      var clause = { alias: alias, field: field, op: op, expected: parseCustomOperand(match[4]), negate: negate };
      if (op === 'IN' && !Array.isArray(clause.expected)) throw new Error('IN requires a list value, for example [1, 2, 3].');
      if (op === '=~') clause.regex = compileCustomRegex(clause.expected);
      return clause;
    });
  });
  return function (row) {
    return groups.some(function (clauses) {
      return clauses.every(function (clause) {
        var actual = customQueryValue(row[clause.alias], clause.field);
        function compare(value) {
          if (clause.op === 'IS NULL') return value == null;
          if (clause.op === 'IS NOT NULL') return value != null;
          // Cypher comparisons with null/missing values evaluate to null,
          // which does not pass a WHERE predicate.
          if (value == null || clause.expected == null) return false;
          if (clause.op === '=') return value === clause.expected || String(value).toLowerCase() === String(clause.expected).toLowerCase();
          if (clause.op === '!=' || clause.op === '<>') return !(value === clause.expected || String(value).toLowerCase() === String(clause.expected).toLowerCase());
          if (clause.op === '<') return Number(value) < Number(clause.expected);
          if (clause.op === '>') return Number(value) > Number(clause.expected);
          if (clause.op === '<=') return Number(value) <= Number(clause.expected);
          if (clause.op === '>=') return Number(value) >= Number(clause.expected);
          if (clause.op === 'IN') return clause.expected.some(function (item) { return item === value || String(item).toLowerCase() === String(value).toLowerCase(); });
          if (clause.op === '=~') return clause.regex.test(value == null ? '' : String(value));
          var haystack = value == null ? '' : String(value).toLowerCase();
          var needle = clause.expected == null ? '' : String(clause.expected).toLowerCase();
          if (clause.op === 'CONTAINS') return haystack.indexOf(needle) !== -1;
          if (clause.op === 'STARTS WITH') return haystack.indexOf(needle) === 0;
          return needle === '' || haystack.slice(-needle.length) === needle;
        }
        // Preserve Cypher's three-valued WHERE behavior: NOT null is still
        // null and therefore must not turn a missing property into a match.
        if ((actual == null || clause.expected === null) &&
            clause.op !== 'IS NULL' && clause.op !== 'IS NOT NULL') return false;
        var result = clause.any
          ? (Array.isArray(actual) && actual.some(compare))
          : compare(actual);
        return clause.negate ? !result : result;
      });
    });
  };
}

function inlinePropertiesToWhere(raw, alias) {
  if (!raw || !raw.trim()) return [];
  return splitCustomOutsideQuotes(raw, ',').map(function (entry) {
    var match = entry.match(/^\s*([A-Za-z_]\w*)\s*:\s*(.+)\s*$/);
    if (!match) throw new Error('Could not parse inline property: ' + entry);
    // Parse now for an immediate, precise literal error; compileCustomWhere
    // performs the same safe parse when it builds the predicate.
    parseCustomLiteral(match[2]);
    return alias + '.' + match[1] + ' = ' + match[2].trim();
  });
}

function parseCustomPatternChain(pattern, nodeToken, edgeToken) {
  var first = pattern.match(new RegExp('^' + nodeToken));
  if (!first) return null;
  var nodes = [{
    alias: first[1] || '_n0',
    kind: first[2] || '',
    properties: first[3] || ''
  }];
  var segments = [], remaining = pattern.slice(first[0].length);
  var tailPattern = new RegExp('^\\s*(<-|-)\\s*(' + edgeToken + ')\\s*(->|-)\\s*' + nodeToken);
  while (remaining.trim()) {
    var part = remaining.match(tailPattern);
    if (!part) return null;
    if (part[1] === '<-' && part[8] === '->') throw new Error('A relationship cannot have arrows at both ends.');
    var range = part[2].match(/\*(\d+)?(?:\.\.(\d+)?)?/);
    var hasRange = !!range;
    var hasOpenRange = hasRange && range[0].indexOf('..') !== -1;
    var minHops = hasRange ? Number(range[1] === undefined ? 1 : range[1]) : 1;
    // In Cypher, *3 means exactly three hops; only *3.. is open-ended.
    var maxHops = hasRange
      ? (hasOpenRange ? Number(range[2] === undefined ? 12 : range[2]) : minHops)
      : 1;
    if (maxHops < minHops) throw new Error('Relationship range maximum must be at least its minimum.');
    segments.push({
      alias: part[3] || '_r' + segments.length,
      kinds: part[4] ? part[4].split('|').map(function (kind) { return kind.replace(/^\s*:/, '').trim(); }) : [],
      properties: part[7] || '',
      direction: part[1] === '<-' ? 'in' : (part[8] === '->' ? 'out' : 'both'),
      minHops: Math.max(0, minHops),
      maxHops: Math.min(12, maxHops),
      variableLength: hasRange
    });
    nodes.push({
      alias: part[9] || '_n' + nodes.length,
      kind: part[10] || '',
      properties: part[11] || ''
    });
    remaining = remaining.slice(part[0].length);
  }
  return segments.length ? { nodes: nodes, segments: segments } : null;
}

function normalizeCustomQueryEscapes(raw) {
  // Queries copied from Markdown commonly contain \[, \], \(, \), or \*
  // around Cypher syntax. Remove those transport escapes only outside quoted
  // literals so a property value such as 'DOMAIN\\user' remains untouched.
  var result = '', quote = '', escaped = false;
  for (var i = 0; i < raw.length; i++) {
    var ch = raw[i];
    if (quote) {
      result += ch;
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      result += ch;
      continue;
    }
    if (ch === '\\' && i + 1 < raw.length && '[]()*|'.indexOf(raw[i + 1]) !== -1) {
      result += raw[++i];
      continue;
    }
    result += ch;
  }
  return result;
}

function customClauseTokens(raw) {
  var masked = '', quote = '', escaped = false;
  for (var i = 0; i < raw.length; i++) {
    var ch = raw[i];
    if (quote) {
      masked += ' ';
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = '';
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      masked += ' ';
    } else {
      masked += ch;
    }
  }
  var tokens = [], re = /\bOPTIONAL\s+MATCH\b|\bMATCH\b|\bRETURN\b/gi, match;
  while ((match = re.exec(masked))) {
    tokens.push({ keyword: match[0].replace(/\s+/g, ' ').toUpperCase(), index: match.index, end: re.lastIndex });
  }
  return tokens;
}

function parseComposedCustomQuery(normalized) {
  // Consecutive MATCH clauses pass their existing bindings forward in Cypher.
  // For graph rendering, support the common BloodHound form where subsequent
  // MATCH/OPTIONAL MATCH paths are rooted at the node bound by the first MATCH.
  var tokens = customClauseTokens(normalized);
  var returnToken = tokens.find(function (token) { return token.keyword === 'RETURN'; });
  var matchTokens = tokens.filter(function (token) {
    return token.keyword === 'MATCH' || token.keyword === 'OPTIONAL MATCH';
  });
  if (!returnToken || matchTokens.length < 2) return null;
  if (tokens.some(function (token) { return token.index > returnToken.index; })) {
    throw new Error('MATCH clauses must appear before RETURN.');
  }
  var returnTail = normalized.slice(returnToken.end).trim();
  var returnParts = returnTail.match(/^([\s\S]+?)(?:\s+LIMIT\s+(\d+))?$/i);
  var clauseTexts = matchTokens.map(function (token, index) {
    var end = index + 1 < matchTokens.length ? matchTokens[index + 1].index : returnToken.index;
    return normalized.slice(token.end, end).trim();
  });
  var base = parseCustomQuery('MATCH ' + clauseTexts[0] + ' RETURN _base');
  if (!base.nodeAlias) throw new Error('The initial MATCH in a composed query must bind one node.');
  var branches = clauseTexts.slice(1).map(function (text, index) {
    var branch = parseCustomQuery('MATCH ' + text + ' RETURN _branch');
    if (!branch.chain) throw new Error('Each subsequent MATCH must contain a relationship pattern.');
    if (branch.chain.nodes[0].alias !== base.nodeAlias) {
      throw new Error('Each subsequent MATCH must start from the initial alias "' + base.nodeAlias + '".');
    }
    return { query: branch, optional: matchTokens[index + 1].keyword === 'OPTIONAL MATCH' };
  });
  return {
    composedMatches: true,
    baseQuery: base,
    branches: branches,
    returnExpression: returnParts[1].trim(),
    limit: Math.max(1, Math.min(QUERY_TOTAL_CAP, Number(returnParts[2]) || QUERY_TOTAL_CAP)),
    requestedLimit: returnParts[2] ? Number(returnParts[2]) : null
  };
}

function parseCustomQuery(raw) {
  // Accept normal Cypher and Markdown/JSON-transport escaped punctuation.
  var normalized = normalizeCustomQueryEscapes(raw.trim()).replace(/;$/, '');
  if (!normalized) throw new Error('Enter a query first.');
  var composed = parseComposedCustomQuery(normalized);
  if (composed) return composed;
  var query = normalized.match(/^MATCH\s+([\s\S]+?)(?:\s*WHERE\s+([\s\S]+?))?\s*RETURN\s+([\s\S]+?)(?:\s+LIMIT\s+(\d+))?$/i);
  if (!query) throw new Error('Expected MATCH … [WHERE …] RETURN … [LIMIT number].');

  var pattern = query[1].trim();
  var leadingDeclarations = [];
  // BloodHound commonly declares endpoints before a named path:
  // MATCH (n:Computer),(m:Group {...}),p=shortestPath((n)-[*1..]->(m))
  var compoundPattern = pattern.match(/^([\s\S]+),\s*([A-Za-z_]\w*\s*=[\s\S]+)$/);
  if (compoundPattern) {
    leadingDeclarations = splitCustomOutsideQuotes(compoundPattern[1], ',');
    pattern = compoundPattern[2].trim();
  }
  var pathAlias = '';
  var pathFunction = '';
  var pathAssignment = pattern.match(/^([A-Za-z_]\w*)\s*=\s*([\s\S]+)$/);
  if (pathAssignment) { pathAlias = pathAssignment[1]; pattern = pathAssignment[2].trim(); }
  var pathCall = pattern.match(/^(shortestPath|allShortestPaths)\s*\(([\s\S]*)\)$/i);
  if (pathCall) {
    pathFunction = pathCall[1].toLowerCase();
    pattern = pathCall[2].trim();
    // Several BloodHound examples wrap the path in one extra pair.
    if (pattern[0] === '(' && pattern[1] === '(' && pattern.slice(-2) === '))') pattern = pattern.slice(1, -1);
  }
  var nodeToken = '\\(\\s*([A-Za-z_]\\w*)?\\s*(?::\\s*([A-Za-z_]\\w*))?\\s*(?:\\{\\s*([^{}]*?)\\s*\\})?\\s*\\)';
  var edgeToken = '\\[\\s*([A-Za-z_]\\w*)?\\s*(?::\\s*([A-Za-z_]\\w*(?:\\s*\\|\\s*:?[A-Za-z_]\\w*)*))?\\s*(?:\\*(\\d+)?(?:\\.\\.(\\d+)?)?)?\\s*(?:\\{\\s*([^{}]*?)\\s*\\})?\\s*\\]';
  var chain = parseCustomPatternChain(pattern, nodeToken, edgeToken);
  var single = pattern.match(new RegExp('^' + nodeToken + '$'));
  if (!chain && !single) {
    throw new Error('Could not parse MATCH pattern. Node and chained relationship patterns are supported.');
  }

  var parsed;
  var inlineConditions = [];
  if (chain) {
    var firstNode = chain.nodes[0], lastNode = chain.nodes[chain.nodes.length - 1], firstEdge = chain.segments[0];
    parsed = {
      chain: chain,
      leftAlias: firstNode.alias, leftKind: firstNode.kind,
      edgeAlias: firstEdge.alias, edgeKinds: firstEdge.kinds,
      rightAlias: lastNode.alias, rightKind: lastNode.kind,
      direction: firstEdge.direction, minHops: firstEdge.minHops, maxHops: firstEdge.maxHops,
      variableLength: chain.segments.some(function (segment) { return segment.variableLength; }),
      pathAlias: pathAlias, pathFunction: pathFunction
    };
    parsed.edgeKind = parsed.edgeKinds.length === 1 ? parsed.edgeKinds[0] : '';
    parsed.aliases = chain.nodes.map(function (node) { return node.alias; })
      .concat(chain.segments.map(function (segment) { return segment.alias; }));
    if (pathAlias) parsed.aliases.push(pathAlias);
    chain.nodes.forEach(function (node) {
      inlineConditions = inlineConditions.concat(inlinePropertiesToWhere(node.properties, node.alias));
    });
    chain.segments.forEach(function (segment) {
      inlineConditions = inlineConditions.concat(inlinePropertiesToWhere(segment.properties, segment.alias));
    });
    leadingDeclarations.forEach(function (declaration) {
      var declared = declaration.match(new RegExp('^' + nodeToken + '$'));
      if (!declared || !declared[1]) throw new Error('Could not parse endpoint declaration: ' + declaration);
      var node = chain.nodes.find(function (item) { return item.alias === declared[1]; });
      if (!node) throw new Error('Endpoint declaration "' + declared[1] + '" is not used by the path.');
      if (declared[2]) node.kind = declared[2];
      inlineConditions = inlineConditions.concat(inlinePropertiesToWhere(declared[3], node.alias));
    });
    parsed.leftKind = chain.nodes[0].kind;
    parsed.rightKind = chain.nodes[chain.nodes.length - 1].kind;
  } else {
    if (pathAlias || pathFunction) throw new Error('Named paths and path functions require a relationship pattern.');
    parsed = { nodeAlias: single[1] || '_node', nodeKind: single[2] || '', aliases: [single[1] || '_node'] };
    inlineConditions = inlinePropertiesToWhere(single[3], parsed.nodeAlias);
  }
  if (new Set(parsed.aliases).size !== parsed.aliases.length) throw new Error('Each node and relationship needs a unique alias.');

  // This viewer renders the matched subgraph rather than a tabular projection,
  // so accept Cypher-style RETURN expressions (p, n.name, DISTINCT(...),
  // COUNT(...), aliases and ORDER BY) without trying to emulate Neo4j's table.
  // The MATCH bindings still determine which nodes and edges appear.
  parsed.returnExpression = query[3].trim();
  var testInline = compileCustomWhere(inlineConditions.join(' AND '), parsed.aliases);
  var testExplicit = compileCustomWhere(query[2], parsed.aliases);
  parsed.testWhere = function (row) { return testInline(row) && testExplicit(row); };
  parsed.limit = Math.max(1, Math.min(QUERY_TOTAL_CAP, Number(query[4]) || QUERY_TOTAL_CAP));
  parsed.requestedLimit = query[4] ? Number(query[4]) : null;
  return parsed;
}

var customAdjacencyCache = new Map(), customAdjacencyGraph = null, customAdjacencyRevision = -1;
function customQueryAdjacency(kinds, direction) {
  var revision = graphRevision(graph);
  if (customAdjacencyGraph !== graph || customAdjacencyRevision !== revision) {
    customAdjacencyCache.clear(); customAdjacencyGraph = graph; customAdjacencyRevision = revision;
  }
  var normalizedKinds = kinds.map(function (kind) { return kind.toLowerCase(); }).sort();
  var key = direction + '|' + normalizedKinds.join('|');
  if (customAdjacencyCache.has(key)) return customAdjacencyCache.get(key);
  var allowed = new Set(normalizedKinds), adjacency = new Map();
  function add(from, to, edge) { indexPush(adjacency, from, { nodeId: to, edge: edge }); }
  getGraphIndex().allEdges.forEach(function (edge) {
    if (allowed.size && !allowed.has(String(edge.kind || '').toLowerCase())) return;
    if (direction === 'out') add(edge.from, edge.to, edge);
    else if (direction === 'in') add(edge.to, edge.from, edge);
    else { add(edge.from, edge.to, edge); add(edge.to, edge.from, edge); }
  });
  customAdjacencyCache.set(key, adjacency);
  return adjacency;
}

function evaluateVariablePathQuery(query, allowedStartIds) {
  var nodeIds = new Set(), resultEdges = [], seenEdges = new Set(), seenPaths = new Set();
  var totalMatches = 0, truncated = false, expansions = 0;
  var adjacency = customQueryAdjacency(query.edgeKinds, query.direction);

  var starts = [];
  graph.nodes.forEach(function (node) {
    if ((!allowedStartIds || allowedStartIds.has(node.id)) &&
        (!query.leftKind || node.kind.toLowerCase() === query.leftKind.toLowerCase())) starts.push(node);
  });

  for (var si = 0; si < starts.length && totalMatches < query.limit; si++) {
    var start = starts[si];
    var queue = [{ id: start.id, nodes: [start.id], edges: [] }];
    var qi = 0, shortestDepth = null;
    while (qi < queue.length && totalMatches < query.limit) {
      var state = queue[qi++];
      var depth = state.edges.length;
      if (depth >= query.minHops) {
        var end = graph.nodes.get(state.id);
        if (end && (!query.rightKind || end.kind.toLowerCase() === query.rightKind.toLowerCase())) {
          var row = {};
          row[query.leftAlias] = start;
          row[query.rightAlias] = end;
          row[query.edgeAlias] = state.edges[state.edges.length - 1];
          if (query.pathAlias) row[query.pathAlias] = state;
          if (query.testWhere(row)) {
            var pathKey = pathIdentityKey(state.nodes, state.edges);
            if (!seenPaths.has(pathKey)) {
              seenPaths.add(pathKey); totalMatches++;
              var additions = state.nodes.filter(function (id) { return !nodeIds.has(id); }).length;
              if (nodeIds.size + additions > QUERY_TOTAL_CAP) { truncated = true; break; }
              state.nodes.forEach(function (id) { nodeIds.add(id); });
              state.edges.forEach(function (edge) {
                var key = edgeVariantKey(edge);
                if (!seenEdges.has(key)) { seenEdges.add(key); resultEdges.push(edge); }
              });
              if (query.pathFunction === 'shortestpath') shortestDepth = depth;
            }
          }
        }
      }
      if (depth >= query.maxHops || (shortestDepth !== null && depth >= shortestDepth)) continue;
      var next = adjacency.get(state.id) || [];
      for (var ni = 0; ni < next.length; ni++) {
        if (state.nodes.indexOf(next[ni].nodeId) !== -1) continue; // paths never revisit a node
        expansions++;
        if (expansions > 25000) { truncated = true; break; }
        queue.push({
          id: next[ni].nodeId,
          nodes: state.nodes.concat([next[ni].nodeId]),
          edges: state.edges.concat([next[ni].edge])
        });
      }
      if (expansions > 25000) break;
    }
    if (expansions > 25000 || nodeIds.size >= QUERY_TOTAL_CAP) { truncated = true; break; }
  }
  return { nodeIds: nodeIds, edges: resultEdges, totalMatches: totalMatches, truncated: truncated };
}

function evaluateChainedPathQuery(query, allowedStartIds) {
  var nodeIds = new Set(), resultEdges = [], seenEdges = new Set(), seenPaths = new Set();
  var totalMatches = 0, truncated = false, expansions = 0;
  var adjacencyBySegment = query.chain.segments.map(function (segment) {
    return customQueryAdjacency(segment.kinds, segment.direction);
  });

  var startSpec = query.chain.nodes[0];
  var starts = [];
  graph.nodes.forEach(function (node) {
    if ((!allowedStartIds || allowedStartIds.has(node.id)) &&
        (!startSpec.kind || node.kind.toLowerCase() === startSpec.kind.toLowerCase())) starts.push(node);
  });

  for (var si = 0; si < starts.length && totalMatches < query.limit; si++) {
    var start = starts[si];
    var initialRow = {}; initialRow[startSpec.alias] = start;
    var frontier = [{ id: start.id, nodes: [start.id], edges: [], row: initialRow }];

    for (var segmentIndex = 0; segmentIndex < query.chain.segments.length && frontier.length; segmentIndex++) {
      var segment = query.chain.segments[segmentIndex];
      var targetSpec = query.chain.nodes[segmentIndex + 1];
      var adjacency = adjacencyBySegment[segmentIndex];
      var nextFrontier = [];

      for (var fi = 0; fi < frontier.length; fi++) {
        var base = frontier[fi];
        var queue = [{ id: base.id, nodes: [], edges: [] }], qi = 0;
        while (qi < queue.length) {
          var walk = queue[qi++], depth = walk.edges.length;
          if (depth >= segment.minHops) {
            var target = graph.nodes.get(walk.id);
            if (target && (!targetSpec.kind || target.kind.toLowerCase() === targetSpec.kind.toLowerCase())) {
              var row = Object.assign({}, base.row);
              row[targetSpec.alias] = target;
              row[segment.alias] = walk.edges[walk.edges.length - 1];
              nextFrontier.push({
                id: walk.id,
                nodes: base.nodes.concat(walk.nodes),
                edges: base.edges.concat(walk.edges),
                row: row
              });
              if (nextFrontier.length >= 5000) { truncated = true; break; }
            }
          }
          if (depth >= segment.maxHops) continue;
          var next = adjacency.get(walk.id) || [];
          for (var ni = 0; ni < next.length; ni++) {
            if (base.nodes.indexOf(next[ni].nodeId) !== -1 || walk.nodes.indexOf(next[ni].nodeId) !== -1) continue;
            expansions++;
            if (expansions > 25000) { truncated = true; break; }
            queue.push({
              id: next[ni].nodeId,
              nodes: walk.nodes.concat([next[ni].nodeId]),
              edges: walk.edges.concat([next[ni].edge])
            });
          }
          if (expansions > 25000 || nextFrontier.length >= 5000) break;
        }
        if (expansions > 25000 || nextFrontier.length >= 5000) break;
      }
      frontier = nextFrontier;
      if (expansions > 25000) break;
    }

    if (query.pathFunction === 'shortestpath' && frontier.length) {
      frontier.sort(function (a, b) { return a.edges.length - b.edges.length; });
      var shortestLength = frontier[0].edges.length;
      frontier = frontier.filter(function (state) { return state.edges.length === shortestLength; });
    }

    for (var ri = 0; ri < frontier.length && totalMatches < query.limit; ri++) {
      var result = frontier[ri];
      if (query.pathAlias) result.row[query.pathAlias] = result;
      if (!query.testWhere(result.row)) continue;
      var key = pathIdentityKey(result.nodes, result.edges);
      if (seenPaths.has(key)) continue;
      seenPaths.add(key); totalMatches++;
      var additions = result.nodes.filter(function (id) { return !nodeIds.has(id); }).length;
      if (nodeIds.size + additions > QUERY_TOTAL_CAP) { truncated = true; break; }
      result.nodes.forEach(function (id) { nodeIds.add(id); });
      result.edges.forEach(function (edge) {
        var edgeKey = edgeVariantKey(edge);
        if (!seenEdges.has(edgeKey)) { seenEdges.add(edgeKey); resultEdges.push(edge); }
      });
    }
    if (expansions > 25000 || nodeIds.size >= QUERY_TOTAL_CAP) { truncated = true; break; }
  }
  return { nodeIds: nodeIds, edges: resultEdges, totalMatches: totalMatches, truncated: truncated };
}

function evaluateFixedRelationshipQuery(query, allowedStartIds) {
  var nodeIds = new Set(), edges = [], totalMatches = 0, truncated = false;
  var allowedEdgeKinds = new Set(query.edgeKinds.map(function (kind) { return kind.toLowerCase(); }));
  function kindMatches(node, kind) {
    return !!node && (!kind || node.kind.toLowerCase() === kind.toLowerCase());
  }
  var candidateEdges = allowedEdgeKinds.size
    ? Array.from(allowedEdgeKinds).reduce(function (all, kind) {
        return all.concat(getGraphIndex().edgesByKind.get(kind) || []);
      }, [])
    : getGraphIndex().allEdges;
  candidateEdges.forEach(function (edge) {
    if (allowedEdgeKinds.size && !allowedEdgeKinds.has(String(edge.kind).toLowerCase())) return;
    var left = graph.nodes.get(query.direction === 'in' ? edge.to : edge.from);
    var right = graph.nodes.get(query.direction === 'in' ? edge.from : edge.to);
    var orientations = [{ left: left, right: right }];
    if (query.direction === 'both') {
      orientations.push({ left: graph.nodes.get(edge.to), right: graph.nodes.get(edge.from) });
    }
    var matched = orientations.some(function (orientation) {
      if (allowedStartIds && (!orientation.left || !allowedStartIds.has(orientation.left.id))) return false;
      if (!kindMatches(orientation.left, query.leftKind) || !kindMatches(orientation.right, query.rightKind)) return false;
      var row = {};
      row[query.leftAlias] = orientation.left;
      row[query.edgeAlias] = edge;
      row[query.rightAlias] = orientation.right;
      return query.testWhere(row);
    });
    if (!matched) return;
    totalMatches++;
    var additions = (nodeIds.has(edge.from) ? 0 : 1) + (nodeIds.has(edge.to) ? 0 : 1);
    if (edges.length >= query.limit || nodeIds.size + additions > QUERY_TOTAL_CAP) {
      truncated = true;
      return;
    }
    nodeIds.add(edge.from);
    nodeIds.add(edge.to);
    edges.push(edge);
  });
  return { nodeIds: nodeIds, edges: edges, totalMatches: totalMatches, truncated: truncated };
}

var parsedCustomQueryCache = new Map();
function runCustomQuery(raw) {
  var status = byId('customQueryStatus');
  status.classList.remove('queryError');
  if (!graph.nodes.size) {
    status.textContent = 'Load data before running a custom query.';
    status.classList.add('queryError');
    return;
  }
  var query;
  try {
    query = parsedCustomQueryCache.get(raw);
    if (!query) {
      query = parseCustomQuery(raw); parsedCustomQueryCache.set(raw, query);
      if (parsedCustomQueryCache.size > 25) parsedCustomQueryCache.delete(parsedCustomQueryCache.keys().next().value);
    }
  } catch (err) {
    status.textContent = err.message;
    status.classList.add('queryError');
    return;
  }

  var nodeIds = new Set(), edges = [], totalMatches = 0, truncated = false;
  function kindMatches(node, kind) { return !!node && (!kind || node.kind.toLowerCase() === kind.toLowerCase()); }
  if (query.composedMatches) {
    var baseIds = new Set();
    graph.nodes.forEach(function (node) {
      var row = {}; row[query.baseQuery.nodeAlias] = node;
      if (kindMatches(node, query.baseQuery.nodeKind) && query.baseQuery.testWhere(row)) baseIds.add(node.id);
    });
    var seenOptionalEdges = new Set();
    baseIds.forEach(function (baseId) {
      var baseResultIds = new Set([baseId]), baseResultEdges = [], baseMatches = 1, survives = true;
      query.branches.forEach(function (clause) {
        if (!survives) return;
        var branch = clause.query, oneStart = new Set([baseId]);
        var branchResult = branch.variableLength || branch.pathFunction || branch.chain.segments.length > 1
          ? (branch.chain.segments.length > 1
            ? evaluateChainedPathQuery(branch, oneStart)
            : evaluateVariablePathQuery(branch, oneStart))
          : evaluateFixedRelationshipQuery(branch, oneStart);
        if (!clause.optional && !branchResult.totalMatches) {
          survives = false;
          return;
        }
        branchResult.nodeIds.forEach(function (id) { baseResultIds.add(id); });
        branchResult.edges.forEach(function (edge) { baseResultEdges.push(edge); });
        baseMatches += branchResult.totalMatches;
        truncated = truncated || branchResult.truncated;
      });
      if (!survives) return;
      baseResultIds.forEach(function (id) {
        if (nodeIds.size < QUERY_TOTAL_CAP && nodeIds.size < query.limit) nodeIds.add(id);
        else if (!nodeIds.has(id)) truncated = true;
      });
      baseResultEdges.forEach(function (edge) {
        var key = edgeVariantKey(edge);
        if (!seenOptionalEdges.has(key)) {
          seenOptionalEdges.add(key);
          edges.push(edge);
        }
      });
      totalMatches += baseMatches;
    });
    // A renderer limit may omit a branch endpoint; never pass a dangling
    // relationship to vis-network when that happens.
    edges = edges.filter(function (edge) {
      return nodeIds.has(edge.from) && nodeIds.has(edge.to);
    });
  } else if (query.nodeAlias) {
    graph.nodes.forEach(function (node) {
      if (!kindMatches(node, query.nodeKind) || !query.testWhere((function () { var row = {}; row[query.nodeAlias] = node; return row; })())) return;
      totalMatches++;
      if (nodeIds.size < query.limit) nodeIds.add(node.id); else truncated = true;
    });
    edges = graph.edges.filter(function (edge) { return nodeIds.has(edge.from) && nodeIds.has(edge.to); }).slice(0, 1000);
  } else if (query.variableLength || query.pathFunction || (query.chain && query.chain.segments.length > 1)) {
    var pathResult = query.chain && query.chain.segments.length > 1
      ? evaluateChainedPathQuery(query)
      : evaluateVariablePathQuery(query);
    nodeIds = pathResult.nodeIds;
    edges = pathResult.edges;
    totalMatches = pathResult.totalMatches;
    truncated = pathResult.truncated;
  } else {
    var fixedResult = evaluateFixedRelationshipQuery(query);
    nodeIds = fixedResult.nodeIds;
    edges = fixedResult.edges;
    totalMatches = fixedResult.totalMatches;
    truncated = fixedResult.truncated;
  }

  if (!totalMatches) {
    status.textContent = 'Query ran successfully: no matches.';
    setGraphAreaState('graph');
    drawGraph(new Set(), [], { caption: 'Custom query — no matches' });
    return;
  }
  if (query.requestedLimit && query.requestedLimit > QUERY_TOTAL_CAP) truncated = true;
  status.textContent = totalMatches.toLocaleString() + ' match' + (totalMatches === 1 ? '' : 'es') +
    '; showing ' + nodeIds.size.toLocaleString() + ' node' + (nodeIds.size === 1 ? '' : 's') +
    (truncated ? ' (limited).' : '.');
  setGraphAreaState('graph');
  drawGraph(nodeIds, edges, {
    // Query matches are explicit result rows, not incidental neighbors. Pin all
    // of them so persisted node/edge filters cannot turn a successful custom
    // query into an apparently blank graph. Edge filters may still hide lines,
    // but the matched endpoints remain visible and inspectable.
    pinnedIds: new Set(nodeIds),
    caption: 'Custom query — ' + totalMatches.toLocaleString() + ' match' + (totalMatches === 1 ? '' : 'es') + (truncated ? ' (truncated)' : '')
  });
}

function runQuery(queryDef) {
  if (!graph.nodes.size) { showToast('Load some data first.'); return; }
  var result = queryDef.run();
  if (!result) { showSavedQueryInspector(queryDef, result); showToast('No results for "' + queryDef.label + '" in the loaded data.'); return; }
  if (result.empty) { showSavedQueryInspector(queryDef, result); showToast(result.caption || ('No results for "' + queryDef.label + '".')); return; }
  setGraphAreaState('graph');
  drawGraph(result.nodeIds, result.edges, { caption: result.caption, pinnedIds: result.pinnedIds });
  showSavedQueryInspector(queryDef, result);
}
