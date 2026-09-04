// Contextual guidance and explainable attack-path suggestions.
// This is advisory only: BloodHound relationships describe possible control,
// not proof that an action will succeed in the current environment.

var suggestedAttackPaths = [];
var guidancePathCache = new Map();
var guidancePathSequence = 0;
var guidanceIndexCache = null;
var guidanceSearchCache = new Map();
var guidanceSearchCacheGraph = null;
var pathTuning = {
  targetMode: 'all', optimize: 'highest', maxHops: 12,
  allowSessions: true, allowInherited: true, allowCrossDomain: true, ownedOnly: false
};

var RELATION_GUIDANCE = {
  genericall: { title: 'Full control', detail: 'The source can control the target object. Inspect the target type and the relationship finding for applicable lab validation.', weight: 1 },
  genericwrite: { title: 'Writable target', detail: 'The source can modify security-relevant target attributes. Inspect the edge to see target-specific possibilities.', weight: 2 },
  writedacl: { title: 'Writable permissions', detail: 'The source can change the target DACL and grant additional control rights.', weight: 1 },
  writeowner: { title: 'Ownership takeover', detail: 'The source can become owner and may then rewrite the target DACL.', weight: 1 },
  owns: { title: 'Object ownership', detail: 'The source owns the target and may be able to grant itself additional rights.', weight: 1 },
  forcechangepassword: { title: 'Password reset path', detail: 'The source can reset the target user password without knowing its current value.', weight: 1 },
  allextendedrights: { title: 'Extended control rights', detail: 'The source holds all extended rights over the target; inspect the target type for the resulting capability.', weight: 2 },
  addmember: { title: 'Group membership control', detail: 'The source can add a principal to the target group and inherit that group’s privileges.', weight: 1 },
  addself: { title: 'Self-membership path', detail: 'The source can add itself to the target group and inherit its privileges.', weight: 1 },
  writespn: { title: 'Writable SPN', detail: 'The source can set an SPN on the target account, potentially creating a targeted Kerberoast opportunity.', weight: 2 },
  addkeycredentiallink: { title: 'Shadow credential path', detail: 'The source can write key-credential material on the target identity.', weight: 1 },
  adminto: { title: 'Local administrator access', detail: 'The source has local administrator rights on the target computer.', weight: 1 },
  canrdp: { title: 'Remote Desktop access', detail: 'The source can establish an RDP session on the target, subject to credentials and host controls.', weight: 3 },
  canpsremote: { title: 'PowerShell remoting access', detail: 'The source can use PowerShell remoting against the target computer.', weight: 2 },
  executedcom: { title: 'DCOM execution access', detail: 'The source may be able to execute remotely through DCOM on the target.', weight: 3 },
  allowedtodelegate: { title: 'Constrained delegation path', detail: 'The source is configured to delegate Kerberos authentication to the target service or computer.', weight: 3 },
  allowedtoact: { title: 'RBCD path', detail: 'The source is allowed to act on behalf of users against the target computer.', weight: 1 },
  readlapspassword: { title: 'Readable LAPS password', detail: 'The source can read the managed local administrator password for the target computer.', weight: 1 },
  readgmsapassword: { title: 'Readable gMSA password', detail: 'The source can retrieve password material for the target managed service account.', weight: 1 },
  dcsync: { title: 'Directory replication rights', detail: 'The source has a computed DCSync relationship against the target domain.', weight: 1 },
  getchanges: { title: 'Partial replication rights', detail: 'GetChanges contributes to DCSync when paired with GetChangesAll on the same domain.', weight: 2 },
  getchangesall: { title: 'Partial replication rights', detail: 'GetChangesAll contributes to DCSync when paired with GetChanges on the same domain.', weight: 2 },
  manageca: { title: 'Certificate authority control', detail: 'The source can administer the target enterprise CA.', weight: 1 },
  managecertificates: { title: 'Certificate issuance control', detail: 'The source can manage certificate requests on the target CA.', weight: 2 },
  enroll: { title: 'Certificate enrollment', detail: 'The source can enroll in the target template. Review template settings and publication before treating it as exploitable.', weight: 3 },
  memberof: { title: 'Group-derived access', detail: 'The source inherits privileges and access assigned to the destination group.', weight: 2 },
  hassession: { title: 'Collected user session', detail: 'A user session was observed on this computer. Session data is point-in-time and may now be stale.', weight: 3 },
  sidhistory: { title: 'Historical SID influence', detail: 'Historical SID data may preserve access granted to the previous identity.', weight: 3 },
  hassidhistory: { title: 'Historical SID influence', detail: 'Historical SID data may preserve access granted to the previous identity.', weight: 3 }
};

function relationshipExplanation(edge, fromNode, toNode) {
  var kind = String(edge && edge.kind || 'Relationship');
  var lower = kind.toLowerCase();
  var source = fromNode ? displayName(fromNode) : String(edge && edge.from || 'the source');
  var target = toNode ? displayName(toNode) : String(edge && edge.to || 'the destination');
  var explanation = {
    meaning: source + ' has the collected ' + kind + ' relationship to ' + target + '.',
    direction: 'The arrow runs from the relationship source to its destination.'
  };

  if (lower === 'hassession') return {
    meaning: target + ' has a collected session on ' + source + '.',
    direction: 'The Computer → User arrow represents possible credential or token traversal after the computer is controlled. It does not mean the computer logged on to the user. Session evidence is point-in-time and may be stale.'
  };
  if (lower === 'memberof') return {
    meaning: source + ' is a member of ' + target + '.',
    direction: 'The Member → Group arrow follows privilege inheritance: the member receives rights assigned to the group.'
  };
  if (lower === 'hassidhistory' || lower === 'sidhistory') return {
    meaning: source + ' carries the SID of ' + target + ' in SID history.',
    direction: 'The arrow points from the current principal to the historical identity whose permissions may be inherited.'
  };
  if (lower === 'contains') return {
    meaning: source + ' contains ' + target + ' in the collected directory hierarchy.',
    direction: 'This is a hierarchy edge from parent to child, not proof that the parent is compromised or controls every child.'
  };
  if (lower === 'gplink') return {
    meaning: source + ' is linked to ' + target + ' and may apply policy to objects in that scope.',
    direction: 'The arrow runs GPO → linked container to show policy scope; it does not mean the container owns the GPO.'
  };
  if (lower === 'spntarget') return {
    meaning: source + ' has a service principal name associated with a service target on ' + target + '.',
    direction: 'This identifies the service target. It does not by itself grant the account access to the computer.'
  };
  if (/^(trust|trustedby|sameforesttrust|crossforesttrust)$/.test(lower)) return {
    meaning: source + ' trusts ' + target + ' according to the collected trust direction.',
    direction: 'Trust direction describes which domain accepts identities from the other domain; it is not evidence that either domain is already controlled.'
  };
  if (lower === 'publishedto') return {
    meaning: 'Certificate template ' + source + ' is published by ' + target + '.',
    direction: 'The Template → CA arrow makes enrollment-path traversal possible; publication alone is not an exploitable template condition.'
  };
  if (lower === 'hostscaservice') return {
    meaning: source + ' hosts the certificate authority service ' + target + '.',
    direction: 'The Computer → CA arrow records service hosting, not automatic control of the CA through the computer relationship alone.'
  };
  if (lower === 'issuedsignedby') return {
    meaning: source + ' is signed or issued by ' + target + '.',
    direction: 'The arrow follows the certificate chain from the issued certificate authority toward its signer.'
  };
  if (lower === 'trustedforntauth') return {
    meaning: source + ' is trusted for domain authentication through ' + target + '.',
    direction: 'The CA → NTAuth store arrow represents PKI trust, not ownership of the trust store.'
  };
  if (/^(enterprisecafor|rootcafor|aiacafor|ntauthstorefor)$/.test(lower)) return {
    meaning: source + ' is associated with the domain ' + target + '.',
    direction: 'This is PKI-to-domain scope information, not a standalone privilege-escalation edge.'
  };
  if (lower === 'extendedbypolicy') return {
    meaning: source + ' references issuance policy ' + target + '.',
    direction: 'The arrow records certificate policy extension; it does not by itself grant enrollment or control.'
  };
  if (lower === 'oidgrouplink') return {
    meaning: 'Issuance policy ' + source + ' is linked to group ' + target + '.',
    direction: 'The arrow records an OID-to-group association; additional certificate conditions determine whether privilege can flow.'
  };
  if (lower === 'allowedtodelegate') return {
    meaning: source + ' is configured for constrained delegation to a service associated with ' + target + '.',
    direction: 'The arrow follows the possible delegation path from the configured principal to the service target.'
  };
  if (lower === 'allowedtoact') return {
    meaning: target + ' allows ' + source + ' to act on behalf of users through resource-based constrained delegation.',
    direction: 'The Principal → Computer arrow shows who is trusted to impersonate users to the destination computer.'
  };
  if (lower === 'adminto') return {
    meaning: source + ' has collected local administrator access to ' + target + '.',
    direction: 'The Principal → Computer arrow follows potential control of the destination computer.'
  };
  if (lower === 'canrdp') return {
    meaning: source + ' has collected Remote Desktop access to ' + target + '.',
    direction: 'The Principal → Computer arrow shows possible interactive logon; it does not guarantee administrative privileges or network reachability.'
  };
  if (lower === 'canpsremote') return {
    meaning: source + ' has collected PowerShell remoting access to ' + target + '.',
    direction: 'The Principal → Computer arrow shows possible remote-session access; resulting privilege depends on the account and endpoint configuration.'
  };
  if (lower === 'executedcom') return {
    meaning: source + ' has collected DCOM execution access to ' + target + '.',
    direction: 'The Principal → Computer arrow shows a possible remote-execution route, subject to host and network controls.'
  };
  if (edge && edge.category === 'acl') return {
    meaning: source + ' holds the ' + kind + ' permission over ' + target + '.',
    direction: 'The Principal → Object arrow follows control or permission flow. Inherited rights should be confirmed against the target’s effective ACL.'
  };
  if (edge && edge.category === 'adcs' && /^ADCSESC/i.test(kind)) return {
    meaning: source + ' can reach ' + target + ' through the collected ' + kind + ' certificate-services condition.',
    direction: 'This is a computed AD CS attack-path edge. Validate the documented prerequisites before treating it as exploitable.'
  };
  return explanation;
}

function guidanceForEdge(edge) {
  return RELATION_GUIDANCE[String(edge && edge.kind || '').toLowerCase()] || null;
}

function isAutomatedAttackEdge(edge) {
  var kind = String(edge && edge.kind || '');
  // Enrollment and one half of the DCSync permission pair are useful clues,
  // but are not independently sufficient attack-path steps.
  if (/^(Enroll|GetChanges|GetChangesAll)$/i.test(kind)) return false;
  if (guidanceForEdge(edge)) return true;
  return /^(ADCSESC(?:[1-9]|1[0-5])[A-Z]?|GoldenCert|CoerceAndRelayNTLMTo(?:ADCS|HTTPSCA|HTTPCA)|Trust|TrustedBy|SameForestTrust|CrossForestTrust)$/i.test(kind);
}

function guidanceEdgeWeight(edge) {
  var guidance = guidanceForEdge(edge);
  var weight = guidance ? guidance.weight : (/Trust$/i.test(String(edge.kind || '')) ? 5 : 4);
  if (edge && edge.inherited) weight += 3;
  if (/^HasSession$/i.test(String(edge && edge.kind || ''))) weight += 4;
  var from = graph.nodes.get(edge.from), to = graph.nodes.get(edge.to);
  if ((from && from.isStub) || (to && to.isStub)) weight += 4;
  return weight;
}

function guidanceIndexes() {
  var core = getGraphIndex(), revision = graphRevision(graph);
  if (guidanceIndexCache && guidanceIndexCache.graph === graph && guidanceIndexCache.revision === revision) {
    return guidanceIndexCache;
  }
  var outgoing = new Map(), incoming = new Map();
  function indexEdge(edge) {
    if (!outgoing.has(edge.from)) outgoing.set(edge.from, []);
    if (!incoming.has(edge.to)) incoming.set(edge.to, []);
    outgoing.get(edge.from).push(edge);
    incoming.get(edge.to).push(edge);
  }
  core.allEdges.forEach(function (edge) {
    if (!isAutomatedAttackEdge(edge)) return;
    indexEdge(edge);
  });
  guidanceIndexCache = { graph: graph, revision: revision,
    outgoing: outgoing, incoming: incoming };
  return guidanceIndexCache;
}

function edgeCrossesDomain(edge) {
  var from = graph.nodes.get(edge.from), to = graph.nodes.get(edge.to);
  var fromDomain = nodeDomain(from), toDomain = nodeDomain(to);
  return !!(fromDomain && toDomain && fromDomain !== toDomain);
}

function guidanceEdgeAllowed(edge, tuning) {
  if (!isAutomatedAttackEdge(edge)) return false;
  if (!tuning.allowSessions && /^HasSession$/i.test(String(edge.kind || ''))) return false;
  if (!tuning.allowInherited && edge.inherited) return false;
  if (!tuning.allowCrossDomain && edgeCrossesDomain(edge)) return false;
  return true;
}

function comparePathQuality(a, b, optimize) {
  if (optimize === 'highest') {
    return a.tierRank - b.tierRank || a.cost - b.cost || a.edges.length - b.edges.length;
  }
  if (optimize === 'hops') {
    return a.edges.length - b.edges.length || a.tierRank - b.tierRank || a.cost - b.cost;
  }
  return a.cost - b.cost || a.tierRank - b.tierRank || a.edges.length - b.edges.length;
}

// Uniform-cost enumeration yields a small set of loopless alternatives. It is
// used for one selected object, where explaining meaningful alternatives is
// more useful than returning whichever equal-length BFS path was inserted first.
function rankedPathsFromSource(startId, tiers, tuning, limit) {
  if (!graph.nodes.has(startId)) return [];
  var outgoing = guidanceIndexes().outgoing, targets = new Map(), queue = [], results = [], signatures = new Set();
  tiers.forEach(function (tier) { tier.ids.forEach(function (id) {
    var existing = targets.get(id);
    if (!existing || tier.rank < existing.rank) targets.set(id, tier);
  }); });
  function containsNode(state, id) {
    while (state) { if (state.nodeId === id) return true; state = state.parent; }
    return false;
  }
  function materializeEdges(state) {
    var edges = [];
    while (state && state.via) { edges.push(state.via); state = state.parent; }
    edges.reverse(); return edges;
  }
  heapPush(queue, { nodeId: startId, parent: null, via: null, hops: 0, cost: 0, priority: 0 });
  var expansions = 0, expansionLimit = 25000;
  while (queue.length && results.length < Math.max(limit * 4, 12) && expansions++ < expansionLimit) {
    var state = heapPop(queue), tier = targets.get(state.nodeId);
    if (tier && state.hops) {
      var pathEdges = materializeEdges(state);
      var signature = pathEdges.map(function (edge) { return edgeIdentityKey(edge.from, edge.to, edge.kind); }).join('>');
      if (!signatures.has(signature)) {
        signatures.add(signature);
        results.push({ sourceId: startId, targetId: state.nodeId, edges: pathEdges,
          cost: state.cost, tier: tier.name, tierRank: tier.rank, tierValue: tier.value });
      }
      continue;
    }
    if (state.hops >= tuning.maxHops) continue;
    (outgoing.get(state.nodeId) || []).forEach(function (edge) {
      if (!guidanceEdgeAllowed(edge, tuning) || containsNode(state, edge.to)) return;
      var cost = state.cost + guidanceEdgeWeight(edge);
      var priority = tuning.optimize === 'hops' ? state.hops + 1 : cost;
      heapPush(queue, { nodeId: edge.to, parent: state, via: edge, hops: state.hops + 1,
        cost: cost, priority: priority });
    });
  }
  results.sort(function (a, b) { return comparePathQuality(a, b, tuning.optimize); });
  return results.slice(0, limit);
}

function shortestGuidancePath(startId, targetIds, maxHops) {
  var tier = { name: 'high-value target', rank: 0, value: 80, ids: Array.from(targetIds) };
  var tuning = Object.assign({}, pathTuning, { maxHops: maxHops || pathTuning.maxHops });
  var paths = rankedPathsFromSource(startId, [tier], tuning, 1);
  if (!paths.length) return null;
  paths[0].nodeIds = new Set([startId].concat(paths[0].edges.map(function (edge) { return edge.to; })));
  return paths[0];
}

function pathCaveats(edges) {
  var caveats = [];
  if (edges.some(function (edge) { return edge.kind === 'DCSync' && edge.computed; })) {
    caveats.push('DCSync is computed from paired GetChanges and GetChangesAll rights on the same domain; confirm both effective permissions remain present.');
  }
  if (edges.some(function (edge) { return edge.kind === 'HasSession'; })) {
    caveats.push('Session evidence is point-in-time and may be stale.');
  }
  if (edges.some(function (edge) { return edge.inherited; })) {
    caveats.push('The path includes an inherited permission; confirm inheritance still applies.');
  }
  if (edges.some(function (edge) {
    var from = graph.nodes.get(edge.from), to = graph.nodes.get(edge.to);
    return (from && from.isStub) || (to && to.isStub);
  })) caveats.push('A referenced-only object appears in the path, so its properties may be incomplete.');
  return caveats;
}

function cacheGuidancePath(edges, title, detail, meta) {
  var key = 'guidance-' + (++guidancePathSequence);
  var nodeIds = new Set();
  edges.forEach(function (edge) { nodeIds.add(edge.from); nodeIds.add(edge.to); });
  var caveats = pathCaveats(edges);
  if (meta && meta.assumed) caveats.unshift('The starting point is an assumption, not an object marked Owned. Confirm access before following this path.');
  guidancePathCache.set(key, {
    id: key, title: title, detail: detail, edges: edges.slice(), nodeIds: nodeIds,
    sourceId: meta && meta.sourceId, targetId: meta && meta.targetId,
    caveats: caveats, cost: meta && meta.cost, tier: meta && meta.tier,
    evidenceQuality: meta && meta.evidenceQuality, reason: meta && meta.reason
  });
  if (guidancePathCache.size > 250) guidancePathCache.delete(guidancePathCache.keys().next().value);
  return key;
}

function buildNodeGuidance(node) {
  if (!node) return [];
  var paths = [];
  selectedTargetTiers(pathTuning).forEach(function (tier) {
    paths = paths.concat(rankedPathsFromSource(node.id, [tier], pathTuning, 3));
  });
  paths.sort(function (a, b) { return comparePathQuality(a, b, pathTuning.optimize); });
  return paths.slice(0, 3).map(function (path) {
    var target = graph.nodes.get(path.targetId), evidence = pathEvidenceQuality(path.edges);
    path.title = 'Candidate path to ' + (target ? displayName(target) : path.targetId);
    path.detail = displayName(node) + ' can reach a ' + path.tier + ' through ' + path.edges.length +
      ' collected relationship' + (path.edges.length === 1 ? '' : 's') + '. ' + pathSelectionReason(path, pathTuning.optimize);
    path.evidenceQuality = evidence;
    path.reason = pathSelectionReason(path, pathTuning.optimize);
    return path;
  });
}

function nodeGuidanceHtml(node) {
  var suggestions = buildNodeGuidance(node);
  if (!suggestions.length) {
    return '<div class="nextSteps"><div class="nextStepsHead">Candidate path from selected object</div>' +
      '<div class="nextStepsEmpty">No candidate path from this object to a collected high-value target was found. Missing collection methods can hide paths.</div></div>';
  }
  var primary = suggestions[0], alternatives = suggestions.slice(1);
  function pathCard(item, className) {
    var key = cacheGuidancePath(item.edges, item.title, item.detail, item);
    return '<div class="' + className + '"><div class="nextStepTitle">' + escapeHtml(item.title) + '</div>' +
      '<div class="nextStepDetail">' + escapeHtml(item.detail) + '</div>' +
      '<div class="pathEvidenceLine">' + escapeHtml(item.tier) + ' · ' + item.edges.length + ' hops · cost ' + item.cost +
      ' · ' + escapeHtml(item.evidenceQuality) + ' evidence</div>' +
      '<button type="button" class="miniBtn nextStepPathBtn" data-guidance-path="' + key + '">Show evidence</button></div>';
  }
  return '<div class="nextSteps"><div class="nextStepsHead">Candidate path from selected object</div>' +
    '<div class="nextStepsCaveat">Only the candidate path beginning at this selected object is shown. Collected relationships are not guaranteed exploits.</div>' +
    pathCard(primary, 'nextStepCard') + (alternatives.length ?
      '<details class="nextStepAlternatives"><summary>' + alternatives.length + ' alternative' + (alternatives.length === 1 ? '' : 's') + '</summary>' +
      alternatives.map(function (item) { return pathCard(item, 'nextStepAlternative'); }).join('') + '</details>' : '') + '</div>';
}

function privilegedTargetTiers() {
  var critical = groupIdsByRids(['512', '518', '519']);
  guidanceIndexes().incoming.forEach(function (edges, targetId) {
    var target = graph.nodes.get(targetId);
    if (target && target.kind === 'Domain' && edges.some(function (edge) { return edge.kind === 'DCSync'; }) && critical.indexOf(targetId) === -1) {
      critical.push(targetId);
    }
  });
  var criticalSet = new Set(critical), other = highValueIds().filter(function (id) { return !criticalSet.has(id); });
  var tiers = [];
  if (critical.length) tiers.push({ name: 'forest/domain control', value: 100, rank: 0, ids: critical });
  if (other.length) tiers.push({ name: 'high-value target', value: 80, rank: 1, ids: other });
  return tiers;
}

function selectedTargetTiers(tuning) {
  var tiers = privilegedTargetTiers();
  if (tuning.targetMode === 'privilege') return tiers.filter(function (tier) { return tier.rank === 0; });
  if (tuning.targetMode === 'highvalue') {
    var ids = highValueIds();
    return ids.length ? [{ name: 'high-value target', value: 80, rank: 0, ids: ids }] : [];
  }
  return tiers;
}

function pathEvidenceQuality(edges) {
  var penalty = 0;
  edges.forEach(function (edge) {
    if (/^HasSession$/i.test(String(edge.kind || ''))) penalty += 2;
    if (edge.inherited) penalty += 1;
    var from = graph.nodes.get(edge.from), to = graph.nodes.get(edge.to);
    if ((from && from.isStub) || (to && to.isStub)) penalty += 2;
  });
  return penalty === 0 ? 'high' : (penalty <= 2 ? 'medium' : 'low');
}

function pathSelectionReason(path, optimize) {
  if (optimize === 'highest') return 'Ranked by target privilege, then relationship cost.';
  if (optimize === 'hops') return 'Ranked by hop count, then target privilege and relationship cost.';
  return 'Ranked by relationship reliability, then target privilege and hop count.';
}

function suggestedSources() {
  var sources = [], seen = new Set(), privileged = privilegedPrincipalIds();
  function add(id, entry, bonus, assumed) {
    var node = graph.nodes.get(id);
    if (!node || seen.has(id) || (privileged.has(id) && entry !== 'Owned foothold') || !isEnabledNode(node)) return;
    seen.add(id); sources.push({ id: id, entry: entry, bonus: bonus, assumed: assumed });
  }
  if (ownedNodeIds.size) {
    ownedNodeIds.forEach(function (id) { add(id, 'Owned foothold', 45, false); });
    return sources;
  }

  var broadGroups = [];
  ['DOMAIN USERS@', 'AUTHENTICATED USERS@', 'EVERYONE@', 'DOMAIN COMPUTERS@'].forEach(function (name) {
    broadGroups = broadGroups.concat(findGroupsByPrefix(name));
  });
  nestedMembers(broadGroups).forEach(function (id) {
    var node = graph.nodes.get(id);
    if (node && (node.kind === 'User' || node.kind === 'Computer')) add(id, 'Low-privilege starting assumption', 0, true);
  });
  graph.nodes.forEach(function (node) {
    if (node.kind !== 'User') return;
    if (propertyValue(node, ['dontreqpreauth']) === true) add(node.id, 'AS-REP roast candidate', 15, true);
    else if (propertyValue(node, ['hasspn']) === true) add(node.id, 'Kerberoast candidate', 10, true);
  });
  var outgoing = guidanceIndexes().outgoing;
  sources.sort(function (a, b) {
    return b.bonus - a.bonus || (outgoing.get(b.id) || []).length - (outgoing.get(a.id) || []).length ||
      String(a.id).localeCompare(String(b.id));
  });
  return sources.slice(0, 2000);
}

function heapPush(heap, item) {
  heap.push(item);
  var index = heap.length - 1;
  while (index > 0) {
    var parent = Math.floor((index - 1) / 2);
    if (heap[parent].priority <= item.priority) break;
    heap[index] = heap[parent]; index = parent;
  }
  heap[index] = item;
}

function heapPop(heap) {
  if (!heap.length) return null;
  var first = heap[0], last = heap.pop();
  if (!heap.length) return first;
  var index = 0;
  while (true) {
    var left = index * 2 + 1, right = left + 1, smallest = index;
    if (left < heap.length && heap[left].priority < last.priority) smallest = left;
    if (right < heap.length && heap[right].priority < (smallest === index ? last.priority : heap[left].priority)) smallest = right;
    if (smallest === index) break;
    heap[index] = heap[smallest]; index = smallest;
  }
  heap[index] = last;
  return first;
}

function reverseWeightedGuidance(targetIds, tuning) {
  var incoming = guidanceIndexes().incoming, dist = new Map(), parent = new Map(), heap = [], best = new Map(), labels = new Map();
  targetIds.forEach(function (id) {
    var key = id + '\u0000' + 0;
    dist.set(key, 0); heapPush(heap, { key: key, nodeId: id, hops: 0, priority: 0, targetId: id });
    labels.set(id, [{ hops: 0, cost: 0 }]);
  });
  while (heap.length) {
    var state = heapPop(heap);
    if (dist.get(state.key) !== state.priority) continue;
    if (!(labels.get(state.nodeId) || []).some(function (label) {
      return label.hops === state.hops && label.cost === state.priority;
    })) continue;
    var currentBest = best.get(state.nodeId);
    if (!currentBest || state.priority < currentBest.cost ||
        (state.priority === currentBest.cost && state.hops < currentBest.hops)) {
      best.set(state.nodeId, { key: state.key, cost: state.priority, hops: state.hops, targetId: state.targetId });
    }
    if (state.hops >= tuning.maxHops) continue;
    (incoming.get(state.nodeId) || []).forEach(function (edge) {
      if (!guidanceEdgeAllowed(edge, tuning)) return;
      var hops = state.hops + 1, key = edge.from + '\u0000' + hops;
      var stepCost = tuning.optimize === 'hops' ? 1 : guidanceEdgeWeight(edge);
      var proposed = state.priority + stepCost;
      var nodeLabels = labels.get(edge.from) || [];
      if (nodeLabels.some(function (label) { return label.hops <= hops && label.cost <= proposed; })) return;
      nodeLabels = nodeLabels.filter(function (label) { return !(label.hops >= hops && label.cost >= proposed); });
      nodeLabels.push({ hops: hops, cost: proposed }); labels.set(edge.from, nodeLabels);
      if (!dist.has(key) || proposed < dist.get(key)) {
        dist.set(key, proposed);
        parent.set(key, { edge: edge, nextKey: state.key });
        heapPush(heap, { key: key, nodeId: edge.from, hops: hops, priority: proposed, targetId: state.targetId });
      }
    });
  }
  return { best: best, parent: parent, maxHops: tuning.maxHops };
}

function cachedReverseWeightedGuidance(targetIds, tuning) {
  if (guidanceSearchCacheGraph !== graph) {
    guidanceSearchCache.clear(); guidanceSearchCacheGraph = graph;
  }
  var key = [graphRevision(graph), tuning.optimize, tuning.maxHops, tuning.allowSessions,
    tuning.allowInherited, tuning.allowCrossDomain, targetIds.slice().sort().join('|')].join(';');
  if (guidanceSearchCache.has(key)) return guidanceSearchCache.get(key);
  var result = reverseWeightedGuidance(targetIds, tuning);
  guidanceSearchCache.set(key, result);
  if (guidanceSearchCache.size > 20) guidanceSearchCache.delete(guidanceSearchCache.keys().next().value);
  return result;
}

function pathFromWeightedParents(sourceId, search) {
  var selected = search.best.get(sourceId);
  if (!selected || !selected.hops) return null;
  var edges = [], key = selected.key, guard = 0;
  while (search.parent.has(key) && guard++ < search.maxHops) {
    var step = search.parent.get(key); edges.push(step.edge); key = step.nextKey;
  }
  return edges.length === selected.hops ? { edges: edges, targetId: selected.targetId, cost: selected.cost } : null;
}

function generateSuggestedAttackPaths(limit) {
  limit = limit || 6;
  var tiers = selectedTargetTiers(pathTuning), sources = suggestedSources(), candidates = [], signatures = new Set();
  if (pathTuning.ownedOnly) sources = sources.filter(function (source) { return !source.assumed; });
  tiers.forEach(function (tier) {
    var search = cachedReverseWeightedGuidance(tier.ids, pathTuning);
    sources.forEach(function (source) {
      var path = pathFromWeightedParents(source.id, search);
      if (!path || tier.ids.indexOf(path.targetId) === -1) return;
      var signature = source.id + '|' + path.edges.map(function (edge) {
        return edgeIdentityKey(edge.from, edge.to, edge.kind);
      }).join('>');
      if (signatures.has(signature)) return;
      signatures.add(signature);
      var cost = path.edges.reduce(function (total, edge) { return total + guidanceEdgeWeight(edge); }, 0);
      var sourceNode = graph.nodes.get(source.id), targetNode = graph.nodes.get(path.targetId);
      candidates.push({
        sourceId: source.id, targetId: path.targetId, edges: path.edges,
        sourceName: sourceNode ? displayName(sourceNode) : source.id,
        targetName: targetNode ? displayName(targetNode) : path.targetId,
        entry: source.entry, assumed: source.assumed, tier: tier.name, tierRank: tier.rank,
        score: tier.value + source.bonus - cost * 3 - path.edges.length,
        cost: cost, caveats: pathCaveats(path.edges), evidenceQuality: pathEvidenceQuality(path.edges)
      });
    });
  });
  candidates.sort(function (a, b) {
    var quality = comparePathQuality(a, b, pathTuning.optimize);
    return quality || b.score - a.score || a.sourceName.localeCompare(b.sourceName);
  });
  return candidates.slice(0, limit);
}

function refreshSuggestedAttackPaths() {
  readPathTuningControls();
  suggestedAttackPaths = graph.nodes.size ? generateSuggestedAttackPaths(6) : [];
  renderSuggestedAttackPaths();
}

function readPathTuningControls() {
  var target = byId('pathTargetMode'), optimize = byId('pathOptimizeMode'), maxHops = byId('pathMaxHops');
  if (target) pathTuning.targetMode = target.value;
  if (optimize) pathTuning.optimize = optimize.value;
  if (maxHops) pathTuning.maxHops = Math.max(1, Math.min(20, Number(maxHops.value) || 12));
  var sessions = byId('pathAllowSessions'), inherited = byId('pathAllowInherited');
  var crossDomain = byId('pathAllowCrossDomain'), ownedOnly = byId('pathOwnedOnly');
  if (sessions) pathTuning.allowSessions = sessions.checked;
  if (inherited) pathTuning.allowInherited = inherited.checked;
  if (crossDomain) pathTuning.allowCrossDomain = crossDomain.checked;
  if (ownedOnly) pathTuning.ownedOnly = ownedOnly.checked;
}

function renderSuggestedAttackPaths() {
  var list = byId('suggestedPathList'), status = byId('suggestedPathStatus'), count = byId('suggestedPathCount');
  if (!list || !status || !count) return;
  count.textContent = suggestedAttackPaths.length ? String(suggestedAttackPaths.length) : '';
  if (!graph.nodes.size) {
    status.textContent = 'Load BloodHound data to generate suggestions.';
    list.innerHTML = '';
    return;
  }
  if (!suggestedAttackPaths.length) {
    status.textContent = 'No candidate paths were found. Mark a controlled object as Owned or collect more relationship data.';
    list.innerHTML = '';
    return;
  }
  status.textContent = ownedNodeIds.size
    ? 'Ranked from objects marked Owned.'
    : 'Starting points are assumptions. Mark a controlled object as Owned for precise results.';
  list.innerHTML = suggestedAttackPaths.map(function (path, index) {
    var key = cacheGuidancePath(path.edges, path.sourceName + ' → ' + path.targetName,
      path.entry + '; ' + path.edges.length + ' relationships; heuristic cost ' + path.cost + '. ' +
      pathSelectionReason(path, pathTuning.optimize), Object.assign({}, path, {
        reason: pathSelectionReason(path, pathTuning.optimize)
      }));
    path.cacheKey = key;
    return '<button type="button" class="suggestedPathCard" data-suggested-path="' + key + '">' +
      '<span class="suggestedRank">' + (index + 1) + '</span>' +
      '<span class="suggestedPathBody"><span class="suggestedPathTitle">' + escapeHtml(path.sourceName) + ' → ' + escapeHtml(path.targetName) + '</span>' +
      '<span class="suggestedPathMeta">' + escapeHtml(path.tier) + ' · ' + path.edges.length + ' hops · cost ' + path.cost +
      ' · ' + escapeHtml(path.evidenceQuality) + ' evidence</span></span></button>';
  }).join('');
}

function showGuidancePathInspector(path) {
  var source = path.sourceId && graph.nodes.get(path.sourceId), target = path.targetId && graph.nodes.get(path.targetId);
  var chain = path.edges.map(function (edge) { return edge.kind; }).join(' → ');
  byId('inspector').innerHTML =
    '<div class="inspKindRow"><span class="queryInfoMark">!</span> Candidate Path</div>' +
    '<div class="inspName">' + escapeHtml(path.title) + '</div>' +
    '<div class="queryInfoStatus queryInfoMatched">' + escapeHtml(path.detail) + '</div>' +
    (source || target ? '<div class="guidanceEndpoints"><b>' + escapeHtml(source ? displayName(source) : path.sourceId || 'Start') +
    '</b><span>→</span><b>' + escapeHtml(target ? displayName(target) : path.targetId || 'Target') + '</b></div>' : '') +
    '<div class="queryInfoSection"><div class="queryInfoLabel">Relationship chain</div><div class="queryInfoText">' + escapeHtml(chain) + '</div></div>' +
    (path.tier || path.cost != null || path.evidenceQuality ? '<div class="pathMetricGrid">' +
      (path.tier ? '<div><span>Target tier</span><b>' + escapeHtml(path.tier) + '</b></div>' : '') +
      (path.cost != null ? '<div><span>Heuristic cost</span><b>' + escapeHtml(path.cost) + '</b></div>' : '') +
      (path.evidenceQuality ? '<div><span>Evidence</span><b>' + escapeHtml(path.evidenceQuality) + '</b></div>' : '') +
      '</div>' : '') +
    (path.reason ? '<div class="queryInfoSection"><div class="queryInfoLabel">Why this path</div><div class="queryInfoText">' + escapeHtml(path.reason) + '</div></div>' : '') +
    (path.caveats && path.caveats.length ? '<div class="queryInfoSection"><div class="queryInfoLabel">Validate first</div><ul class="guidanceCaveats">' +
      path.caveats.map(function (item) { return '<li>' + escapeHtml(item) + '</li>'; }).join('') + '</ul></div>' : '') +
    '<div class="queryInfoHint">Select any node or relationship in the path for detailed evidence and lab guidance.</div>';
  rememberInspectorState({ type: 'guidance', id: path.id });
}

function renderGuidancePath(key) {
  var path = guidancePathCache.get(key);
  if (!path || !path.edges.length) return;
  selectedNodeId = null;
  hideFindingPanel();
  setGraphAreaState('graph');
  drawGraph(path.nodeIds, path.edges, {
    pinnedIds: new Set([path.sourceId, path.targetId].filter(Boolean)),
    caption: 'Candidate path — ' + path.title
  });
  showGuidancePathInspector(path);
}
