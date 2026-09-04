// Extracted from NewOne/adCodex-cyberpunk.html; kept as a classic browser script.

// ---------------------------------------------------------------------------
// inspector
// ---------------------------------------------------------------------------
function rememberInspectorState(state) {
  if (currentView) currentView.inspectorState = state || null;
}

function clearInspectorForView(message) {
  selectedNodeId = null;
  byId('inspector').innerHTML = '<div class="placeholder">' +
    escapeHtml(message || 'Select an object or relationship in this view.') + '</div>';
  hideFindingPanel();
  rememberInspectorState(null);
}

function restoreInspectorState(state) {
  if (!state) { clearInspectorForView(); return; }
  if (state.type === 'node' && graph.nodes.has(state.id)) { selectNode(state.id); return; }
  if (state.type === 'edge') {
    var visId = Object.keys(currentVisEdgeMap).find(function (id) {
      return edgeVariantKey(currentVisEdgeMap[id].edge) === state.edgeKey;
    });
    if (visId) { selectEdge(visId); return; }
  }
  if (state.type === 'query') {
    var query = PREMADE_QUERIES.find(function (item) { return item.id === state.id; });
    if (query) { showSavedQueryInspector(query, state.hasMatches ? {} : null); return; }
  }
  if (state.type === 'guidance') {
    var path = guidancePathCache.get(state.id);
    if (path) { showGuidancePathInspector(path); return; }
  }
  clearInspectorForView('The previous Inspector selection is no longer available. Select an object or relationship in this view.');
}

function showSavedQueryInspector(queryDef, result) {
  if (!queryDef) return;
  selectedNodeId = null;
  hideFindingPanel();
  var category = queryDef.category || QUERY_CATEGORY_BY_ID[queryDef.id] || 'Saved query';
  var hasMatches = !!(result && !result.empty);
  byId('inspector').innerHTML =
    '<div class="inspKindRow"><span class="queryInfoMark">?</span> Saved Query</div>' +
    '<div class="inspName">' + escapeHtml(queryDef.label) + '</div>' +
    '<div class="queryInfoCategory">' + escapeHtml(category) + '</div>' +
    '<div class="queryInfoStatus ' + (hasMatches ? 'queryInfoMatched' : 'queryInfoEmpty') + '">' +
      (hasMatches ? 'Matching evidence is shown in the graph.' : 'No matching evidence was found in the loaded data.') +
    '</div>' +
    '<div class="queryInfoSection"><div class="queryInfoLabel">What it does</div>' +
      '<div class="queryInfoText">' + escapeHtml(queryDef.description || 'Runs a saved relationship mapping.') + '</div></div>' +
    '<div class="queryInfoSection"><div class="queryInfoLabel">Why use it</div>' +
      '<div class="queryInfoText">' + escapeHtml(queryDef.use || '') + '</div></div>' +
    '<div class="queryInfoSection"><div class="queryInfoLabel">Collection needed</div>' +
      '<div class="queryInfoText">' + escapeHtml(queryDef.requires || 'Relevant BloodHound collection data.') + '</div></div>' +
    '<div class="queryInfoHint">Select a node or relationship to inspect its details.</div>';
  rememberInspectorState({ type: 'query', id: queryDef.id, hasMatches: hasMatches });
}

function selectNode(id) {
  var previousDirectionAnchor = edgeDirectionAnchorId;
  selectedNodeId = id;
  edgeDirectionAnchorId = id;
  var n = graph.nodes.get(id);
  var el = byId('inspector');
  if (!n) {
    selectedNodeId = null;
    edgeDirectionAnchorId = null;
    el.innerHTML = '<div class="placeholder">Select an object to see its details.</div>';
    hideFindingPanel();
    updateEdgeDirectionControl();
    rememberInspectorState(null);
    return;
  }
  renderFindingPanel(n);
  if (window.matchMedia && window.matchMedia('(max-width:860px)').matches) byId('sidebar').classList.add('mobileOpen');
  var km = KIND_META[n.kind] || KIND_META.Unknown;
  var props = n.properties || {};
  var propRows = Object.keys(props)
    .filter(function (k) { return props[k] !== null && props[k] !== undefined && props[k] !== ''; })
    .sort()
    .map(function (k) {
      return '<tr><td class="pk">' + escapeHtml(k) + '</td><td class="pv">' + escapeHtml(formatPropValue(k, props[k])) + '</td></tr>';
    }).join('');

  var rels = [];
  var selectedIncidentEdges = incidentEdges(id);
  for (var i = 0; i < selectedIncidentEdges.length; i++) {
    var e = selectedIncidentEdges[i];
    if (e.from === id) rels.push({ dir: 'out', other: e.to, kind: e.kind, category: e.category });
    else if (e.to === id) rels.push({ dir: 'in', other: e.from, kind: e.kind, category: e.category });
  }
  rels.sort(function (a, b) { return categoryPriority(a.category) - categoryPriority(b.category); });
  var shown = rels.slice(0, NEIGHBOR_CAP);
  var relRows = shown.map(function (r) {
    var on = graph.nodes.get(r.other);
    var oname = on ? displayName(on) : r.other;
    var arrow = r.dir === 'out' ? '\u2192' : '\u2190';
    return '<div class="relRow" data-id="' + escapeHtml(r.other) + '">' +
      '<span class="relArrow">' + arrow + '</span>' +
      '<span class="relKind">' + escapeHtml(r.kind) + '</span>' +
      '<span class="relTarget">' + escapeHtml(oname) + '</span></div>';
  }).join('');

  var findingTagsHtml = FINDINGS.filter(function (f) { return f.appliesTo(n); })
    .map(function (f) { return ' <span class="tag tagFinding">' + escapeHtml(f.label) + '</span>'; }).join('');
  var owned = ownedNodeIds.has(id);

  el.innerHTML =
    '<div class="inspKindRow"><span class="dot" style="background:' + km.color + '"></span>' + escapeHtml(n.kind) +
      (n.isStub ? ' <span class="tag tagStub">referenced only</span>' : '') +
      (n.highValue ? ' <span class="tag tagHigh">high value</span>' : '') +
      (owned ? ' <span class="tag tagOwned">Owned</span>' : '') + findingTagsHtml + '</div>' +
    '<div class="inspName">' + escapeHtml(displayName(n)) + '</div>' +
    '<div class="inspId">' + escapeHtml(n.id) + '</div>' +
    '<button type="button" class="miniBtn ownedBtn" data-owned-id="' + escapeHtml(n.id) + '">' + (owned ? 'Remove Owned' : 'Mark as Owned') + '</button>' +
    (n.isStub ? '<div class="inspNote">Referenced by another object but not itself included in the loaded files — only its name/ID is known.</div>' : '') +
    nodeGuidanceHtml(n) +
    '<table class="propTable">' + propRows + '</table>' +
    '<div class="relHeader">Relationships (' + rels.length + ')' + (rels.length > shown.length ? ' — showing top ' + shown.length : '') + '</div>' +
    '<div class="relList">' + (relRows || '<div class="placeholder">None found</div>') + '</div>';

  rememberInspectorState({ type: 'node', id: id });

  updateEdgeDirectionControl();
  if (activeEdgeDirection !== 'all' && previousDirectionAnchor !== id && currentView && currentView.nodeIds.has(id)) {
    applyFilters();
  }
}

// ---------------------------------------------------------------------------
// search
// ---------------------------------------------------------------------------
function runSearch(q) {
  q = q.trim().toLowerCase();
  var el = byId('searchResults');
  if (!q) { el.innerHTML = ''; el.style.display = 'none'; return; }

  var matches = [];
  var candidateIds = q.length >= 3 ? (getGraphIndex().searchTrigrams.get(q.slice(0, 3)) || []) : Array.from(graph.nodes.keys());
  for (var candidateIndex = 0; candidateIndex < candidateIds.length; candidateIndex++) {
    var n = graph.nodes.get(candidateIds[candidateIndex]);
    if (!n) continue;
    var normalized = normalizedNodeFields(n);
    if (normalized.nameLower.indexOf(q) !== -1 || normalized.idLower.indexOf(q) !== -1) {
      matches.push(n);
      if (matches.length >= 25) break;
    }
  }

  if (!matches.length) {
    el.innerHTML = '<div class="searchEmpty">No matches</div>';
    el.style.display = 'block';
    return;
  }
  el.innerHTML = matches.map(function (n) {
    var km = KIND_META[n.kind] || KIND_META.Unknown;
    return '<div class="searchRow" data-id="' + escapeHtml(n.id) + '">' +
      '<span class="dot" style="background:' + km.color + '"></span>' +
      '<span class="srName">' + escapeHtml(displayName(n)) + '</span>' +
      '<span class="srKind">' + escapeHtml(n.kind) + '</span></div>';
  }).join('');
  el.style.display = 'block';
}
