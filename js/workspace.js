// Extracted from NewOne/adCodex-cyberpunk.html; kept as a classic browser script.

// ---------------------------------------------------------------------------
// sample data
// ---------------------------------------------------------------------------
function loadSampleData() {
  if (graph.nodes.size > 0 && !confirm('This will replace the currently loaded data with sample data. Continue?')) return;
  graph = makeGraph();
  activeKinds = new Set(KIND_ORDER);
  activeEdgeCategories = new Set(Object.keys(CAT_META));
  activeEdgeKinds = new Set(); edgeKindFiltersInitialized = false; viewHistory = [];
  ownedNodeIds = new Set(); activeOwnedOnly = false;
  ownedFilterBaseView = null;
  selectedNodeId = null;
  currentView = null;
  var results = SAMPLE_FILES.map(function (sf) {
    return Object.assign({ filename: sf.filename }, ingestFile(graph, sf.json, sf.filename));
  });
  afterIngest(results);
}

function clearScene() {
  if (network) { network.destroy(); network = null; }
  currentView = null;
  ownedFilterBaseView = null;
  currentVisEdgeMap = {};
  selectedNodeId = null;
  activeEdgeDirection = 'all';
  edgeDirectionAnchorId = null;
  updateEdgeDirectionControl();
  updateAppliedFilters();
  clearInspectorForView();
  byId('workspaceStatus').style.display = 'none';
  if (graph.nodes.size) {
    setGraphAreaState('ready');
    byId('readyText').textContent = graph.nodes.size.toLocaleString() + ' objects loaded. Search, run a query, or show the entire graph.';
  } else setGraphAreaState('empty');
}

function goBackView() {
  if (!viewHistory.length) return;
  var previous = viewHistory.pop();
  var inspectorState = previous.inspectorState;
  suppressHistory = true;
  setGraphAreaState('graph');
  drawGraph(previous.nodeIds, previous.edges, previous.meta);
  restoreInspectorState(inspectorState);
}

function selectedNodeSet() {
  return new Set(network ? network.getSelectedNodes() : []);
}

function isolateSelection() {
  if (!currentView) return;
  var selected = selectedNodeSet();
  if (!selected.size) return;
  var edges = currentView.edges.filter(function (e) { return selected.has(e.from) && selected.has(e.to); });
  drawGraph(selected, edges, { pinnedIds: selected, caption: 'Isolated selection' });
}

function shortestPathSelection() {
  if (!network || !currentView) return;
  var selected = network.getSelectedNodes();
  if (selected.length !== 2) { showToast('Select exactly two nodes to find a directed path.'); return; }
  function findPath(start, target) {
    var adjacency = new Map();
    currentView.edges.forEach(function (e) { if (!adjacency.has(e.from)) adjacency.set(e.from, []); adjacency.get(e.from).push(e); });
    var queue = [start], seen = new Set([start]), parent = new Map(), qi = 0;
    while (qi < queue.length) {
      var id = queue[qi++];
      if (id === target) break;
      (adjacency.get(id) || []).forEach(function (e) { if (!seen.has(e.to)) { seen.add(e.to); parent.set(e.to, e); queue.push(e.to); } });
    }
    if (!seen.has(target)) return null;
    var edges = [], cursor = target;
    while (cursor !== start) { var edge = parent.get(cursor); edges.push(edge); cursor = edge.from; }
    edges.reverse(); return edges;
  }
  var start = selected[0], target = selected[1], edges = findPath(start, target);
  if (!edges) { start = selected[1]; target = selected[0]; edges = findPath(start, target); }
  if (!edges) { showToast('No directed path exists between the selected nodes in this view.'); return; }
  var nodeIds = new Set([start, target]); edges.forEach(function (e) { nodeIds.add(e.from); nodeIds.add(e.to); });
  drawGraph(nodeIds, edges, { pinnedIds: new Set([start, target]), caption: 'Shortest selected path: ' + displayName(graph.nodes.get(start)) + ' → ' + displayName(graph.nodes.get(target)) });
}

function hideSelection() {
  if (!currentView) return;
  var selected = selectedNodeSet();
  if (!selected.size) return;
  var nodes = new Set(Array.from(currentView.nodeIds).filter(function (id) { return !selected.has(id); }));
  var edges = currentView.edges.filter(function (e) { return nodes.has(e.from) && nodes.has(e.to); });
  drawGraph(nodes, edges, { caption: 'Selection hidden' });
}

function downloadFile(name, content, type) {
  var url = URL.createObjectURL(new Blob([content], { type: type }));
  var a = document.createElement('a'); a.href = url; a.download = name; a.click();
  window.setTimeout(function () { URL.revokeObjectURL(url); }, 0);
}

function exportCurrentView() {
  if (!currentView) { showToast('Draw a graph before exporting.'); return; }
  function includedNode(id) {
    var n = graph.nodes.get(id), meta = currentView.meta || {};
    var pinned = id === meta.centerId ||
      (activeEdgeDirection !== 'all' && id === edgeDirectionAnchorId) ||
      (meta.pinnedIds && meta.pinnedIds.has(id));
    return !!n && (activeKinds.has(n.kind) || pinned) && (!activeOwnedOnly || ownedNodeIds.has(id));
  }
  var exportedEdges = currentView.edges.filter(function (e) {
    var category = CAT_META[e.category] ? e.category : 'structural';
    return activeEdgeCategories.has(category) && activeEdgeKinds.has(e.kind || 'Unknown') &&
      edgePassesDirectionFilter(e) && includedNode(e.from) && includedNode(e.to);
  });
  var exportedNodeIds = new Set();
  exportedEdges.forEach(function (e) { exportedNodeIds.add(e.from); exportedNodeIds.add(e.to); });
  var meta = currentView.meta || {};
  currentView.nodeIds.forEach(function (id) {
    var pinned = id === meta.centerId ||
      (activeEdgeDirection !== 'all' && id === edgeDirectionAnchorId) ||
      (meta.pinnedIds && meta.pinnedIds.has(id));
    if (pinned && includedNode(id)) exportedNodeIds.add(id);
  });
  var data = {
    exportedAt: new Date().toISOString(),
    nodes: Array.from(exportedNodeIds).map(function (id) { return graph.nodes.get(id); }).filter(Boolean),
    edges: exportedEdges,
    filters: { nodeTypes: Array.from(activeKinds), edgeCategories: Array.from(activeEdgeCategories),
      edgeTypes: Array.from(activeEdgeKinds), ownedOnly: activeOwnedOnly,
      edgeDirection: activeEdgeDirection, edgeDirectionAnchorId: edgeDirectionAnchorId },
    ownedNodeIds: Array.from(ownedNodeIds)
  };
  downloadFile('ad-graph-view.json', JSON.stringify(data, null, 2), 'application/json');
}

function saveWorkspacePreferences() {
  try {
    localStorage.setItem('adGraphPolishedWorkspace', JSON.stringify({
      queryHidden: byId('queryPanel').classList.contains('panelHidden'),
      queryWidth: byId('queryPanel').getBoundingClientRect().width,
      inspectorWidth: byId('sidebar').getBoundingClientRect().width,
      groupParallelEdges: groupParallelEdges
    }));
  } catch (_) {}
}

function restoreWorkspacePreferences() {
  try {
    var p = JSON.parse(localStorage.getItem('adGraphPolishedWorkspace') || '{}');
    if (p.queryWidth >= 220 && p.queryWidth <= 500) byId('queryPanel').style.flexBasis = p.queryWidth + 'px';
    if (p.inspectorWidth >= 260 && p.inspectorWidth <= 520) byId('sidebar').style.flexBasis = p.inspectorWidth + 'px';
    if (p.queryHidden || p.queryCollapsed) setExplorerOpen(false, false);
    groupParallelEdges = !!p.groupParallelEdges;
    updateGroupEdgesButton();
    if (window.matchMedia && window.matchMedia('(max-width:860px)').matches) setExplorerOpen(false, false);
    positionExplorerToggle();
  } catch (_) {}
}

function updateGroupEdgesButton() {
  var button = byId('groupEdgesBtn');
  button.setAttribute('aria-pressed', groupParallelEdges ? 'true' : 'false');
  button.title = groupParallelEdges ? 'Ungroup parallel edges' : 'Group parallel edges';
  button.textContent = groupParallelEdges ? 'Ungroup edges' : 'Group edges';
}

function updatePhysicsButton() {
  var button = byId('freezeBtn');
  button.textContent = physicsFrozen ? 'Unfreeze' : 'Freeze';
  button.title = physicsFrozen ? 'Resume physics' : 'Freeze layout';
  button.setAttribute('aria-label', button.title);
  button.setAttribute('aria-pressed', physicsFrozen ? 'false' : 'true');
}

function positionExplorerToggle() {
  var panel = byId('queryPanel'), button = byId('queryToggle');
  var open = !panel.classList.contains('panelHidden');
  var mobile = window.matchMedia && window.matchMedia('(max-width:860px)').matches;
  button.style.left = open ? Math.max(8, panel.getBoundingClientRect().width - 34) + 'px' : '8px';
  if (mobile) button.style.top = '8px';
}

function setExplorerOpen(open, persist) {
  var panel = byId('queryPanel');
  var mobile = window.matchMedia && window.matchMedia('(max-width:860px)').matches;
  panel.classList.toggle('mobileOpen', mobile && open);
  panel.classList.toggle('panelHidden', !open);
  var button = byId('queryToggle');
  button.setAttribute('aria-expanded', open ? 'true' : 'false');
  button.setAttribute('aria-label', open ? 'Close Explore sidebar' : 'Show Explore sidebar');
  button.title = open ? 'Close Explore sidebar' : 'Show Explore sidebar';
  button.innerHTML = open ? '&#8249;' : '&#8250;';
  if (persist !== false) saveWorkspacePreferences();
  window.setTimeout(function () { positionExplorerToggle(); if (network) network.redraw(); }, 0);
}
