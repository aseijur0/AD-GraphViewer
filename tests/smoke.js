#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const applicationFiles = [
  'bloodhound-parser.js',
  'graph-store.js',
  'sample-data.js',
  'utils.js',
  'graph-index.js',
  'adcs-esc.js',
  'file-ingestion.js',
  'filter-engine.js',
  'query-engine.js',
  'guidance-engine.js',
  'graph-renderer.js',
  'findings.js',
  'inspector.js',
  'workspace.js',
  'app.js',
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const indexHtml = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const expectedScriptSources = [
  'js/vendor/vis-network.min.js',
  'js/vendor/jszip.min.js',
].concat(applicationFiles.map((filename) => 'js/' + filename));
const actualScriptSources = Array.from(
  indexHtml.matchAll(/<script\s+src="([^"]+)"\s*><\/script>/g),
  (match) => match[1]
);
assert(
  JSON.stringify(actualScriptSources) === JSON.stringify(expectedScriptSources),
  'Scripts are missing or loaded out of dependency order'
);
assert(/<link rel="stylesheet" href="css\/app\.css">/.test(indexHtml), 'Application stylesheet is not linked');
assert(!/<script>([\s\S]*?)<\/script>/.test(indexHtml), 'Unexpected inline application script remains');
const suggestedSectionIndex = indexHtml.indexOf('id="suggestedPathsSection"');
const findObjectsIndex = indexHtml.indexOf('<summary>Find objects</summary>');
assert(suggestedSectionIndex !== -1 && suggestedSectionIndex < findObjectsIndex,
  'Suggested attack paths must be the first Explore section');
assert(/id="suggestedPathsSection"[^>]*\bhidden\b/.test(indexHtml),
  'Suggested attack paths must be hidden before data is loaded');
const suggestedSectionTag = indexHtml.match(/<details[^>]*id="suggestedPathsSection"[^>]*>/);
assert(suggestedSectionTag && !/\bopen\b/.test(suggestedSectionTag[0]),
  'Suggested attack paths must remain collapsed until the user opens it');
const staticIds = new Set(
  Array.from(indexHtml.matchAll(/\bid="([^"]+)"/g), (match) => match[1])
);
const duplicateIds = Array.from(indexHtml.matchAll(/\bid="([^"]+)"/g), (match) => match[1])
  .filter((id, index, all) => all.indexOf(id) !== index);
assert(duplicateIds.length === 0, 'Duplicate static IDs: ' + duplicateIds.join(', '));

const sources = applicationFiles.map((filename) => {
  const source = fs.readFileSync(path.join(root, 'js', filename), 'utf8');
  new vm.Script(source, { filename });
  return source;
});
const ingestionSource = sources[applicationFiles.indexOf('file-ingestion.js')];
assert(/byId\(['"]suggestedPathsSection['"]\)\.hidden\s*=\s*!hasData/.test(ingestionSource),
  'Suggested attack-path visibility is not tied to loaded data');

for (const vendor of ['jszip.min.js', 'vis-network.min.js']) {
  const source = fs.readFileSync(path.join(root, 'js', 'vendor', vendor), 'utf8');
  new vm.Script(source, { filename: vendor });
}
new vm.Script(fs.readFileSync(path.join(root, 'js', 'ingestion-worker.js'), 'utf8'), { filename: 'ingestion-worker.js' });

const domReferences = new Set();
for (const source of sources) {
  for (const match of source.matchAll(/byId\(['"]([^'"]+)['"]\)/g)) domReferences.add(match[1]);
}
const missingIds = Array.from(domReferences).filter((id) => !staticIds.has(id));
assert(missingIds.length === 0, 'Missing DOM IDs: ' + missingIds.join(', '));

// app.js immediately wires the real DOM. Evaluate every preceding classic
// script together to exercise the shared global scope without mocking a browser.
const coreSource = sources.slice(0, -1).join('\n');
const context = vm.createContext({
  console,
  setTimeout,
  clearTimeout,
  URL,
  Blob,
  Map,
  Set,
  Date,
  JSON,
  Math,
  Array,
  Object,
  String,
  Number,
  RegExp,
  Error,
  assert,
});
vm.runInContext(coreSource, context, { filename: 'adgraph-improved-core.js' });

vm.runInContext(`
  graph = makeGraph();
  var results = SAMPLE_FILES.map(function (sample) {
    return ingestFile(graph, sample.json, sample.filename);
  });
  assert(!results.some(function (result) { return result.error; }), 'Sample ingestion failed');
  reconcileADCSRelationships(graph);
  assert(graph.nodes.size === 26, 'Unexpected sample node count: ' + graph.nodes.size);
  assert(graph.edges.length === 42, 'Unexpected deduplicated sample edge count: ' + graph.edges.length);
  assert(new Set(graph.edges.map(edgeVariantKey)).size === graph.edges.length,
    'Ingestion retained duplicate relationship variants');

  var user = Array.from(graph.nodes.values()).find(function (node) {
    return displayName(node) === 'JDOE@CORP.LOCAL';
  });
  assert(!!user, 'Expected sample user was not found');
  edgeDirectionAnchorId = user.id;
  activeEdgeDirection = 'out';
  assert(!graph.edges.filter(edgePassesDirectionFilter).some(function (edge) {
    return edge.from !== user.id;
  }), 'Outgoing direction filter leaked an incoming edge');
  activeEdgeDirection = 'in';
  assert(!graph.edges.filter(edgePassesDirectionFilter).some(function (edge) {
    return edge.to !== user.id;
  }), 'Incoming direction filter leaked an outgoing edge');
  activeEdgeDirection = 'all';
  assert(graph.edges.filter(edgePassesDirectionFilter).length === graph.edges.length,
    'All direction filter hid relationships');

  var sessionEdge = graph.edges.find(function (edge) { return edge.kind === 'HasSession'; });
  var sessionMeaning = relationshipExplanation(sessionEdge, graph.nodes.get(sessionEdge.from), graph.nodes.get(sessionEdge.to));
  assert(sessionMeaning.meaning === 'ASMITH@CORP.LOCAL has a collected session on WORKSTATION01.CORP.LOCAL.' &&
    /Computer → User/.test(sessionMeaning.direction) && /does not mean/.test(sessionMeaning.direction),
    'HasSession explanation does not clarify the counterintuitive edge direction');
  var membershipEdge = graph.edges.find(function (edge) {
    return edge.kind === 'MemberOf' && edge.from === user.id;
  });
  var membershipMeaning = relationshipExplanation(membershipEdge, graph.nodes.get(membershipEdge.from), graph.nodes.get(membershipEdge.to));
  assert(/is a member of/.test(membershipMeaning.meaning) && /privilege inheritance/.test(membershipMeaning.direction),
    'MemberOf explanation does not distinguish membership from privilege flow');
  [
    ['GPLink', /policy scope/],
    ['SPNTarget', /does not by itself grant/],
    ['PublishedTo', /publication alone/],
    ['Contains', /hierarchy edge/]
  ].forEach(function (check) {
    var edge = graph.edges.find(function (item) { return item.kind === check[0]; });
    var explanation = relationshipExplanation(edge, graph.nodes.get(edge.from), graph.nodes.get(edge.to));
    assert(check[1].test(explanation.direction), check[0] + ' explanation does not clarify its edge direction');
  });
  assert(graph.edges.every(function (edge) {
    var explanation = relationshipExplanation(edge, graph.nodes.get(edge.from), graph.nodes.get(edge.to));
    return !!(explanation.meaning && explanation.direction);
  }), 'A collected relationship is missing plain-language Inspector wording');

  // Viewer-computed AD CS escalation (ESC) relationships — one per supported
  // condition should be derived from the expanded sample collection, each
  // marked computed by the viewer with the inputs it was built from preserved.
  function nodeByName(name) {
    return Array.from(graph.nodes.values()).find(function (node) { return displayName(node) === name; });
  }
  function computedEsc(kind) {
    return (getGraphIndex().edgesByKind.get(kind.toLowerCase()) || []).filter(function (edge) { return edge.computed; });
  }
  var expectedEsc = {
    ADCSESC1:  ['HELP DESK@CORP.LOCAL', 'CORP.LOCAL'],
    ADCSESC2:  ['DOMAIN USERS@CORP.LOCAL', 'CORP.LOCAL'],
    ADCSESC3:  ['DOMAIN USERS@CORP.LOCAL', 'CORP.LOCAL'],
    ADCSESC4:  ['HELP DESK@CORP.LOCAL', 'CORP.LOCAL'],
    ADCSESC6:  ['DOMAIN USERS@CORP.LOCAL', 'CORP.LOCAL'],
    ADCSESC9:  ['DOMAIN USERS@CORP.LOCAL', 'CORP.LOCAL'],
    ADCSESC13: ['DOMAIN USERS@CORP.LOCAL', 'DOMAIN ADMINS@CORP.LOCAL'],
    ADCSESC15: ['DOMAIN USERS@CORP.LOCAL', 'CORP.LOCAL']
  };
  Object.keys(expectedEsc).forEach(function (kind) {
    var want = expectedEsc[kind], from = nodeByName(want[0]), to = nodeByName(want[1]);
    assert(!!from && !!to, 'Expected endpoints for ' + kind + ' were not in the sample');
    var matches = computedEsc(kind).filter(function (edge) { return edge.from === from.id && edge.to === to.id; });
    assert(matches.length === 1, 'Expected exactly one viewer-computed ' + kind + ' relationship (' + want[0] + ' -> ' + want[1] + '), found ' + matches.length);
    var edge = matches[0];
    assert(edge.computed === true && edge.computedBy === 'viewer' && edge.category === 'adcs' && edge.esc === kind.replace('ADCS', ''),
      kind + ' is not clearly labelled as a viewer-computed ESC relationship');
    assert(Array.isArray(edge.evidenceEdges) && edge.evidenceEdges.length >= 2 &&
      edge.evidenceEdges.some(function (ev) { return /^(Enroll|WriteDacl|GenericAll)$/i.test(ev.kind); }) &&
      edge.evidenceEdges.some(function (ev) { return ev.kind === 'PublishedTo'; }),
      kind + ' did not keep the raw enrollment/publication inputs it was built from');
    assert(isAutomatedAttackEdge(edge), kind + ' is not treated as an attack-path edge, so suggested paths cannot traverse AD CS');
  });
  assert(computedEsc('ADCSESC13')[0].evidenceEdges.some(function (ev) { return ev.kind === 'OIDGroupLink'; }),
    'ESC13 must keep the OID-to-group link that makes enrollment grant privileged membership');
  assert(pathCaveats([computedEsc('ADCSESC1')[0]]).some(function (item) { return /computed by the viewer/i.test(item); }),
    'A viewer-computed ESC relationship did not receive a validate-first caveat');

  // AD CS edges must populate the Security Finding tab like other edges do.
  function edgeFindingFor(edge) {
    var fromNode = graph.nodes.get(edge.from), toNode = graph.nodes.get(edge.to);
    for (var i = 0; i < EDGE_FINDINGS.length; i++) {
      if (EDGE_FINDINGS[i].appliesTo(edge, fromNode, toNode)) return EDGE_FINDINGS[i].commands(edge, fromNode, toNode);
    }
    return null;
  }
  ['ADCSESC1', 'ADCSESC2', 'ADCSESC3', 'ADCSESC4', 'ADCSESC6', 'ADCSESC9', 'ADCSESC13', 'ADCSESC15'].forEach(function (kind) {
    var edge = computedEsc(kind)[0], cmds = edge && edgeFindingFor(edge);
    assert(cmds && cmds.linux.length && cmds.windows.length,
      'No Security Finding commands are offered for ' + kind);
    assert(cmds.linux.some(function (c) { return /certipy/i.test(c.cmd); }),
      kind + ' finding is missing a Certipy command');
    assert(cmds.windows.some(function (c) { return /(Certify|Rubeus|StandIn|ForgeCert|PowerView)/.test(c.cmd); }),
      kind + ' finding is missing a Windows (Certify/Rubeus) command');
    var esc1Context = cmds.linux.join(' ');
    assert(esc1Context.indexOf('<template>') === -1 && esc1Context.indexOf('<ca-name>') === -1,
      kind + ' finding did not resolve the certificate template / CA behind the edge');
  });
  ['Enroll', 'ManageCA'].forEach(function (kind) {
    var edge = (getGraphIndex().edgesByKind.get(kind.toLowerCase()) || [])[0];
    assert(edge && edgeFindingFor(edge), 'No Security Finding was offered for the AD CS ' + kind + ' edge');
  });

  // BloodHound CE collectors (SharpHound CE, RustHound-CE) omit the highvalue
  // property, so a raw CE collection has no high-value flags. The viewer must
  // still derive Tier Zero or Suggested Attack Paths comes up empty.
  var savedCollectedGraph = graph;
  graph = makeGraph();
  var CEDS = 'S-1-5-21-77-88-99';
  upsertFullNode(graph, CEDS, 'Domain', { name: 'CE.LOCAL', domain: 'CE.LOCAL', domainsid: CEDS });
  upsertFullNode(graph, CEDS + '-512', 'Group', { name: 'DOMAIN ADMINS@CE.LOCAL', domain: 'CE.LOCAL' });
  upsertFullNode(graph, CEDS + '-516', 'Group', { name: 'DOMAIN CONTROLLERS@CE.LOCAL', domain: 'CE.LOCAL' });
  upsertFullNode(graph, CEDS + '-513', 'Group', { name: 'DOMAIN USERS@CE.LOCAL', domain: 'CE.LOCAL' });
  upsertFullNode(graph, CEDS + '-1601', 'Group', { name: 'HELP DESK@CE.LOCAL', domain: 'CE.LOCAL' });
  upsertFullNode(graph, CEDS + '-1401', 'Computer', { name: 'DC01.CE.LOCAL', domain: 'CE.LOCAL', enabled: true });
  upsertFullNode(graph, CEDS + '-1104', 'User', { name: 'JDOE@CE.LOCAL', domain: 'CE.LOCAL', enabled: true });
  addEdge(graph, CEDS + '-1401', CEDS + '-516', 'MemberOf', 'structural');
  addEdge(graph, CEDS + '-1104', CEDS + '-513', 'MemberOf', 'structural');
  addEdge(graph, CEDS + '-1104', CEDS + '-1601', 'MemberOf', 'structural');
  addEdge(graph, CEDS + '-1601', CEDS + '-1401', 'GenericAll', 'acl');
  invalidateGraphIndexes();
  assert(Array.from(graph.nodes.values()).every(function (node) {
    return !(node.properties && (node.properties.highvalue || node.properties.highValue || node.properties.sensitive));
  }), 'CE-style sample should carry no explicit high-value flags');
  var derivedHighValue = highValueIds();
  assert(derivedHighValue.length >= 3 && derivedHighValue.indexOf(CEDS) !== -1 && derivedHighValue.indexOf(CEDS + '-512') !== -1,
    'Tier Zero was not derived for a CE collection with no highvalue flags');
  assert(graph.nodes.get(CEDS + '-512').highValue === true && graph.nodes.get(CEDS + '-512')._derivedHighValue === true &&
    graph.nodes.get(CEDS + '-1401').highValue === true,
    'Derived Tier Zero did not flag the Domain Admins group and the domain controller');
  ownedNodeIds.clear();
  var cePaths = generateSuggestedAttackPaths(6);
  assert(cePaths.length > 0 && cePaths.some(function (path) { return derivedHighValue.indexOf(path.targetId) !== -1; }),
    'Suggested Attack Paths is empty for a CE collection despite a derivable path to Tier Zero');
  graph = savedCollectedGraph;
  invalidateGraphIndexes();
  ownedNodeIds.add(user.id);

  // Universal collector support: CE-only collection types are skipped cleanly,
  // ContainedBy containment is parsed, and privileged groups are matched by
  // well-known RID even when the group display name differs (renamed/localised).
  var savedForCollectorTest = graph;
  graph = makeGraph();
  var CID = 'S-1-5-21-5-6-7';
  upsertFullNode(graph, CID, 'Domain', { name: 'CORP2.LOCAL', domain: 'CORP2.LOCAL', domainsid: CID });
  var siteResult = ingestFile(graph, { meta: { type: 'sites', version: 6 },
    data: [{ ObjectIdentifier: 'SITE-1', Properties: { name: 'Default-First-Site' }, Aces: [] }] }, 'x_sites.json');
  assert(siteResult.ignored === true && !siteResult.error && !graph.nodes.has('SITE-1'),
    'A CE sites collection should be skipped cleanly rather than reported as an error');
  var groupsResult = ingestFile(graph, { meta: { type: 'groups', version: 6 }, data: [
    { ObjectIdentifier: CID + '-512', Properties: { name: 'LES ADMINS DU DOMAINE@CORP2.LOCAL', domain: 'CORP2.LOCAL' },
      Aces: [], Members: [], ContainedBy: { ObjectIdentifier: CID + '-CN-USERS', ObjectType: 'Container' } }
  ] }, 'x_groups.json');
  assert(!groupsResult.error, 'A CE groups collection failed to load');
  assert(domainAdminGroupIds().indexOf(CID + '-512') !== -1,
    'Domain Admins was not matched by RID when the group display name is non-standard');
  assert(graph.edges.some(function (e) { return e.kind === 'Contains' && e.from === CID + '-CN-USERS' && e.to === CID + '-512'; }),
    'ContainedBy was not parsed into a Contains relationship');
  graph = savedForCollectorTest;
  invalidateGraphIndexes();

  // Source fallback: with nothing Owned and no resolvable broad-group members
  // (e.g. a collector that omits primary-group membership), enabled users must
  // still seed Suggested Attack Paths so it is not silently empty.
  var savedForSourceTest = graph, savedOwnedSet = ownedNodeIds;
  graph = makeGraph();
  ownedNodeIds = new Set();
  var SID3 = 'S-1-5-21-9-9-9';
  upsertFullNode(graph, SID3, 'Domain', { name: 'LAB3.LOCAL', domain: 'LAB3.LOCAL', domainsid: SID3 });
  upsertFullNode(graph, SID3 + '-512', 'Group', { name: 'DOMAIN ADMINS@LAB3.LOCAL', domain: 'LAB3.LOCAL' });
  upsertFullNode(graph, SID3 + '-1337', 'User', { name: 'ORPHAN@LAB3.LOCAL', domain: 'LAB3.LOCAL', enabled: true });
  addEdge(graph, SID3 + '-1337', SID3 + '-512', 'GenericAll', 'acl');
  invalidateGraphIndexes();
  assert(suggestedSources().some(function (s) { return s.id === SID3 + '-1337'; }),
    'Enabled users were not used as fallback starting points when no broad-group members resolved');
  var fallbackPaths = generateSuggestedAttackPaths(6);
  assert(fallbackPaths.length > 0 && fallbackPaths.some(function (p) { return p.sourceId === SID3 + '-1337'; }),
    'Suggested Attack Paths is empty when membership is absent but an attack edge to Tier Zero exists');
  graph = savedForSourceTest;
  ownedNodeIds = savedOwnedSet;
  invalidateGraphIndexes();

  // AD CS CA infrastructure is Tier Zero: controlling an enterprise/root CA is
  // domain-equivalent (Golden Certificate / ESC7), so a path that ends at the CA
  // must register as reaching a target even though collectors don't flag it.
  var savedForCaTest = graph, savedOwnedCa = ownedNodeIds;
  graph = makeGraph();
  ownedNodeIds = new Set();
  var LID = 'S-1-5-21-4-4-4';
  upsertFullNode(graph, LID, 'Domain', { name: 'LAB4.LOCAL', domain: 'LAB4.LOCAL', domainsid: LID });
  upsertFullNode(graph, LID + '-1201', 'User', { name: 'LOWUSER@LAB4.LOCAL', domain: 'LAB4.LOCAL', enabled: true });
  upsertFullNode(graph, 'LAB4-CA', 'EnterpriseCA', { name: 'LAB4-CA@LAB4.LOCAL', domain: 'LAB4.LOCAL' });
  addEdge(graph, LID + '-1201', 'LAB4-CA', 'GenericAll', 'adcs');
  invalidateGraphIndexes();
  var caHighValue = highValueIds();
  assert(caHighValue.indexOf('LAB4-CA') !== -1 && graph.nodes.get('LAB4-CA').highValue === true,
    'Enterprise CA was not treated as Tier Zero / high value');
  var caPaths = generateSuggestedAttackPaths(6);
  assert(caPaths.some(function (p) { return p.targetId === 'LAB4-CA' && p.sourceId === LID + '-1201'; }),
    'A path that compromises the CA did not register as reaching Tier Zero');
  graph = savedForCaTest;
  ownedNodeIds = savedOwnedCa;
  invalidateGraphIndexes();

  // Item 1: AD CS queries report absence clearly instead of looking clean.
  var potentialEscResult = PREMADE_QUERIES.find(function (q) { return q.id === 'adcs-potential-esc'; }).run();
  var computedEscTotal = getGraphIndex().allEdges.filter(function (e) { return e.computed && /^ADCSESC/i.test(e.kind); }).length;
  assert(computedEscTotal >= 8 && potentialEscResult && !potentialEscResult.empty && potentialEscResult.edges.length === computedEscTotal,
    'Viewer-computed ESC query did not surface every derived relationship');
  assert(computedEsc('ADCSESC7').length >= 1,
    'ESC7 (CA administration/takeover) was not derived from the sample CA control rights');
  assert(computedEsc('ADCSESC16').length >= 1,
    'ESC16 (CA-wide disabled SID security extension) was not derived from the sample CA');
  assert(isAutomatedAttackEdge({ kind: 'ADCSESC16' }),
    'ADCSESC16 must be recognized as an attack-path edge (regex must not cap at ESC15)');
  var computedPathsResult = PREMADE_QUERIES.find(function (q) { return q.id === 'adcs-escalations'; }).run();
  assert(computedPathsResult && computedPathsResult.empty && /No computed ESC relationships in this dataset/.test(computedPathsResult.caption),
    'Computed ESC Paths query did not report the absence of BloodHound CE post-processed data');

  // Items 2/3/4: the Inspector AD CS review for a template.
  var esc1Template = nodeByName('USER AUTH ESC1@CORP.LOCAL');
  var templateSummary = adcsInspectorHtml(esc1Template);
  assert(/Settings that matter/.test(templateSummary) && /ESC conditions/.test(templateSummary),
    'Template Inspector summary is missing the settings or ESC pass/fail section');
  assert(/Enrollee-supplied subject/.test(templateSummary) && /VULNERABLE/.test(templateSummary) &&
    /Windows event IDs/.test(templateSummary) && /4886/.test(templateSummary) && /Remediation/.test(templateSummary),
    'Template Inspector summary did not flag ESC1 with defensive context (event IDs and remediation)');
  assert(/Who can effectively enroll/.test(templateSummary) && /JDOE@CORP.LOCAL/.test(templateSummary) && /via HELP DESK@CORP.LOCAL/.test(templateSummary),
    'Effective-enroller view did not combine CA/template enroll rights with nested group membership');
  var caSummary = adcsInspectorHtml(nodeByName('CORP-CA-SAN@CORP.LOCAL'));
  assert(/CA accepts requester-supplied SAN/.test(caSummary) && /VULNERABLE/.test(caSummary) && /EDITF_ATTRIBUTESUBJECTALTNAME2/.test(caSummary),
    'CA Inspector summary did not flag the ESC6 SAN condition');

  function savedQuery(id) {
    return PREMADE_QUERIES.find(function (query) { return query.id === id; });
  }
  ownedNodeIds.add(user.id);
  var ownedPath = savedQuery('owned-to-da').run();
  assert(ownedPath && !ownedPath.empty && ownedPath.edges.length,
    'Owned-to-Domain-Admins query did not find the sample attack path');
  var weightedPath = savedQuery('easiest-owned-to-hvt').run();
  assert(weightedPath && !weightedPath.empty && weightedPath.edges.length,
    'Lowest-cost owned path query did not find the sample attack path');
  assert(savedQuery('lateral-movement').run().edges.length >= 3,
    'Lateral movement query missed collected access relationships');
  assert(savedQuery('logged-on-privileged-users').run().edges.some(function (edge) {
    return edge.kind === 'HasSession';
  }), 'Privileged session query missed the sample Domain Admin session');
  assert(savedQuery('cross-domain-membership').run() === null,
    'Same-domain group membership was incorrectly classified as cross-domain');
  assert(savedQuery('cross-domain-acls').run() === null,
    'Same-domain ACL was incorrectly classified as cross-domain');
  var nodeAdvice = buildNodeGuidance(user);
  assert(nodeAdvice.length >= 1 && nodeAdvice.length <= 3 && nodeAdvice.every(function (path) {
    return path.sourceId === user.id && path.edges.length && path.edges[0].from === user.id;
  }) &&
    nodeAdvice[0].title.indexOf('Candidate path to') === 0,
    'Node guidance alternatives must all begin at the selected object');
  assert(nodeAdvice[0].edges.length && nodeAdvice[0].edges[0].from === user.id,
    'Selected-object candidate path does not begin at the selected object');
  var selectedGuidanceHtml = nodeGuidanceHtml(user);
  assert((selectedGuidanceHtml.match(/nextStepCard/g) || []).length === 1 &&
    /Candidate path from selected object/.test(selectedGuidanceHtml) &&
    (!/nextStepAlternatives/.test(selectedGuidanceHtml) || /<details class="nextStepAlternatives">/.test(selectedGuidanceHtml)),
    'Inspector must render one primary path and keep same-source alternatives collapsed');
  var automaticPaths = generateSuggestedAttackPaths(6);
  assert(automaticPaths.length > 0 && automaticPaths[0].sourceId === user.id,
    'Suggested attack paths were not ranked from the Owned sample user');
  // With AD CS data present, the strongest suggested paths from the Owned user
  // now traverse computed ESC relationships, so confirm those reach a target
  // and that point-in-time session evidence is still flagged as stale wherever
  // a HasSession edge appears on a path.
  assert(automaticPaths.some(function (path) {
    return path.edges.some(function (edge) { return edge.computed && /^ADCSESC/i.test(edge.kind); });
  }), 'Suggested attack paths did not traverse any computed AD CS escalation relationship');
  var sampleSessionEdge = graph.edges.find(function (edge) { return edge.kind === 'HasSession'; });
  assert(sampleSessionEdge && pathCaveats([sampleSessionEdge]).some(function (item) { return /stale/.test(item); }),
    'Point-in-time session evidence is not flagged as stale on a candidate path');
  assert(isAutomatedAttackEdge({ kind: 'GenericAll' }) &&
    !isAutomatedAttackEdge({ kind: 'Contains' }) && !isAutomatedAttackEdge({ kind: 'Enroll' }),
    'Automated path filtering accepted a structural or insufficient relationship');
  assert(!guidanceEdgeAllowed(sessionEdge, Object.assign({}, pathTuning, { allowSessions: false })) &&
    !guidanceEdgeAllowed(Object.assign({}, membershipEdge, { kind: 'GenericAll', inherited: true }), Object.assign({}, pathTuning, { allowInherited: false })),
    'Candidate-path evidence filters did not exclude session or inherited relationships');
  var collectedGraph = graph;
  graph = makeGraph();
  ['start', 'middle', 'target', 'replicator', 'domain', 'structural'].forEach(function (id) {
    var node = upsertFullNode(graph, id, id === 'target' ? 'Group' : (id === 'domain' ? 'Domain' : 'User'),
      { name: id + '@LAB.LOCAL', highvalue: id === 'target' });
    node.highValue = id === 'target';
  });
  addEdge(graph, 'start', 'target', 'HasSession', 'access');
  addEdge(graph, 'start', 'middle', 'GenericAll', 'acl');
  addEdge(graph, 'middle', 'target', 'GenericAll', 'acl');
  addEdge(graph, 'replicator', 'domain', 'GetChanges', 'acl');
  addEdge(graph, 'replicator', 'domain', 'GetChangesAll', 'acl');
  addEdge(graph, 'structural', 'target', 'Contains', 'structural');
  var edgeCountBeforeDuplicate = graph.edges.length;
  addEdge(graph, 'start', 'target', 'HasSession', 'access', { collectedAt: 12345 });
  assert(graph.edges.length === edgeCountBeforeDuplicate && graph.edgeByKey.get(edgeVariantKey({
    from: 'start', to: 'target', kind: 'HasSession', inherited: false
  })).collectedAt === 12345, 'Duplicate relationship metadata was not merged into the existing edge');
  guidanceIndexCache = null;
  var syntheticTier = [{ name: 'test target', rank: 0, value: 100, ids: ['target'] }];
  var reliablePaths = rankedPathsFromSource('start', syntheticTier,
    Object.assign({}, pathTuning, { optimize: 'feasible' }), 2);
  var shortPaths = rankedPathsFromSource('start', syntheticTier,
    Object.assign({}, pathTuning, { optimize: 'hops' }), 2);
  assert(reliablePaths[0].edges.length === 2 && !reliablePaths[0].edges.some(function (edge) { return edge.kind === 'HasSession'; }),
    'Feasibility ranking did not prefer stronger evidence over a shorter session path');
  assert(shortPaths[0].edges.length === 1 && shortPaths[0].edges[0].kind === 'HasSession',
    'Fewest-hop ranking did not prefer the direct relationship');
  var computedDCSync = (guidanceIndexes().outgoing.get('replicator') || []).find(function (edge) { return edge.kind === 'DCSync'; });
  assert(computedDCSync && computedDCSync.computed && pathCaveats([computedDCSync]).some(function (item) { return /paired GetChanges/.test(item); }),
    'Paired replication rights were not represented as a clearly labelled computed DCSync step');
  assert((getGraphIndex().edgesByKind.get('dcsync') || []).indexOf(computedDCSync) !== -1,
    'Computed DCSync was not exposed through the shared derived-edge index');
  assert(privilegedTargetTiers().some(function (tier) { return tier.rank === 0 && tier.ids.indexOf('domain') !== -1; }),
    'A domain reachable through paired DCSync rights was not classified as a domain-control target');
  var structuralPath = pathResult(['structural'], ['target'], 'Synthetic attack path');
  assert(structuralPath && structuralPath.empty,
    'Saved attack-path logic traversed a structural Contains relationship');
  graph = collectedGraph;
  guidanceIndexCache = null;
  ownedNodeIds.clear();
  var assumedPaths = generateSuggestedAttackPaths(6);
  assert(assumedPaths.length && assumedPaths.some(function (path) { return path.assumed; }),
    'No clearly labelled low-privilege path was generated without an Owned object');
  var assumedPath = assumedPaths.find(function (path) { return path.assumed; });
  var assumedKey = cacheGuidancePath(assumedPath.edges, 'Assumed path', 'Test path', assumedPath);
  assert(guidancePathCache.get(assumedKey).caveats.some(function (item) { return /assumption/.test(item); }),
    'Assumed starting point did not receive a validation warning');
  ownedNodeIds.add(user.id);

  PREMADE_QUERIES.forEach(function (query) { query.run(); });
  assert(PREMADE_QUERIES.length === 48, 'Unexpected saved query count: ' + PREMADE_QUERIES.length);
  assert(new Set(PREMADE_QUERIES.map(function (query) { return query.id; })).size === PREMADE_QUERIES.length,
    'Saved query IDs must be unique');
  assert(PREMADE_QUERIES.every(function (query) {
    return !!(query.category || QUERY_CATEGORY_BY_ID[query.id]);
  }), 'Every saved query must have a menu category');
  assert(PREMADE_QUERIES.every(function (query) {
    return !!(query.description && query.use && query.requires);
  }), 'Every saved query must include Inspector guidance');
  [
    'owned-to-da', 'easiest-owned-to-hvt', 'asrep-roastable', 'laps-readers', 'gmsa-readers',
    'dangerous-direct-rights', 'lateral-movement', 'constrained-delegation', 'rbcd',
    'writable-gpo-impact', 'deep-group-nesting', 'circular-group-nesting',
    'cross-domain-membership', 'cross-domain-acls', 'attack-path-chokepoints'
  ].forEach(function (id) {
    assert(PREMADE_QUERIES.some(function (query) { return query.id === id; }), 'Missing saved query: ' + id);
  });
  var fakeQueryMarkup = '';
  var fakeQueryList = { value: 'owned-to-da' };
  Object.defineProperty(fakeQueryList, 'innerHTML', {
    get: function () { return fakeQueryMarkup; },
    set: function (value) { fakeQueryMarkup = value; fakeQueryList.value = ''; }
  });
  byId = function (id) { return id === 'queryList' ? fakeQueryList : null; };
  renderQueryList();
  assert((fakeQueryList.innerHTML.match(/<optgroup /g) || []).length === 9,
    'Saved query menu did not render all workflow groups');
  assert((fakeQueryList.innerHTML.match(/<option value=/g) || []).length === PREMADE_QUERIES.length + 1,
    'Saved query menu did not render every query');
  assert(fakeQueryList.value === 'owned-to-da',
    'Saved query selection was not preserved when the menu was rendered again');
  var fakeInspector = { innerHTML: '' };
  var fakeFindingPanel = { innerHTML: 'stale finding', style: { display: 'flex' } };
  byId = function (id) {
    if (id === 'inspector') return fakeInspector;
    if (id === 'findingPanel') return fakeFindingPanel;
    return null;
  };
  showSavedQueryInspector(savedQuery('asrep-roastable'), null);
  assert(fakeInspector.innerHTML.indexOf('Find AS-REP Roastable Users') !== -1 &&
    fakeInspector.innerHTML.indexOf('What it does') !== -1 &&
    fakeInspector.innerHTML.indexOf('Collection needed') !== -1,
    'Saved query guidance was not rendered in the Inspector');
  assert(fakeFindingPanel.style.display === 'none' && fakeFindingPanel.innerHTML === '',
    'Saved query guidance did not clear a stale finding panel');
  [
    'MATCH (n:Computer) WHERE n.enabled = true RETURN n LIMIT 100',
    'MATCH (u:User {dontreqpreauth: true}) RETURN u',
    'MATCH p=(u:User)-[r:MemberOf*1..]->(g:Group {highvalue:true}) RETURN p'
  ].forEach(function (query) { parseCustomQuery(query); });

  var restoredInspectorState = null;
  var expectedInspectorState = { type: 'node', id: user.id };
  viewHistory = [{ nodeIds: new Set([user.id]), edges: [], meta: { caption: 'Earlier view' },
    inspectorState: expectedInspectorState }];
  currentView = { nodeIds: new Set(), edges: [], meta: {}, inspectorState: null };
  setGraphAreaState = function () {};
  drawGraph = function (nodeIds, edges, meta) {
    currentView = { nodeIds: nodeIds, edges: edges, meta: meta, inspectorState: null };
  };
  restoreInspectorState = function (state) { restoredInspectorState = state; };
  goBackView();
  assert(restoredInspectorState === expectedInspectorState && currentView.meta.caption === 'Earlier view',
    'Back navigation did not restore the Inspector state belonging to the previous graph view');
`, context);

assert(!/byId\(['"]queryList['"]\)\.addEventListener\(['"]change['"][\s\S]{0,300}e\.target\.value\s*=\s*['"]{2}/.test(sources[sources.length - 1]),
  'Saved-query change handler clears the selected query');

console.log('ADGraph Optimized smoke tests passed');
console.log('- ' + applicationFiles.length + ' application scripts and 2 vendor scripts parse');
console.log('- ' + domReferences.size + ' DOM references resolve');
console.log('- selected-object guidance, Inspector history, relationship explanations, and saved queries pass');
