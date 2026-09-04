// Extracted from NewOne/adCodex-cyberpunk.html; kept as a classic browser script.

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------
function renderFullGraph() {
  setGraphAreaState('graph');
  drawGraph(new Set(graph.nodes.keys()), getGraphIndex().allEdges, {});
}

function showNeighborhood(centerId) {
  var center = graph.nodes.get(centerId);
  if (!center) return;
  setGraphAreaState('graph');

  var related = incidentEdges(centerId).slice();
  related.sort(function (a, b) { return categoryPriority(a.category) - categoryPriority(b.category); });
  var capped = related.length > NEIGHBOR_CAP;
  var shown = capped ? related.slice(0, NEIGHBOR_CAP) : related;

  var nodeIds = new Set([centerId]);
  shown.forEach(function (e) { nodeIds.add(e.from); nodeIds.add(e.to); });

  drawGraph(nodeIds, shown, { centerId: centerId, capped: capped, totalRelCount: related.length });
}

function openSelectiveExpand(centerId) {
  var center = graph.nodes.get(centerId);
  if (!center) return;
  expandNodeId = centerId;
  byId('expandNodeName').textContent = displayName(center);
  var kinds = new Set();
  incidentEdges(centerId).forEach(function (e) { kinds.add(e.kind); });
  byId('expandKinds').innerHTML = Array.from(kinds).sort().map(function (k) {
    return '<label class="filterRow"><input type="checkbox" data-expand-kind="' + escapeHtml(k) + '" checked><span>' + escapeHtml(k) + '</span></label>';
  }).join('') || '<div class="placeholder">No relationships</div>';
  byId('expandPanel').style.display = 'block';
}

function runSelectiveExpand() {
  if (!expandNodeId) return;
  var direction = byId('expandDirection').value;
  var limit = Math.max(1, Math.min(QUERY_TOTAL_CAP, parseInt(byId('expandLimit').value, 10) || 50));
  var kinds = new Set(Array.prototype.map.call(byId('expandKinds').querySelectorAll('input:checked'), function (i) { return i.getAttribute('data-expand-kind'); }));
  var related = incidentEdges(expandNodeId).filter(function (e) {
    return kinds.has(e.kind) && ((direction === 'both' && (e.from === expandNodeId || e.to === expandNodeId)) ||
      (direction === 'out' && e.from === expandNodeId) || (direction === 'in' && e.to === expandNodeId));
  });
  related.sort(function (a, b) { return categoryPriority(a.category) - categoryPriority(b.category); });
  var totalRelCount = related.length;
  var capped = totalRelCount > limit;
  related = related.slice(0, limit);
  var nodeIds = new Set([expandNodeId]);
  related.forEach(function (e) { nodeIds.add(e.from); nodeIds.add(e.to); });
  byId('expandPanel').style.display = 'none';
  setGraphAreaState('graph');
  drawGraph(nodeIds, related, { centerId: expandNodeId, capped: capped, totalRelCount: totalRelCount,
    caption: 'Selective expansion from ' + displayName(graph.nodes.get(expandNodeId)) +
      (capped ? ' — showing ' + related.length + ' of ' + totalRelCount + ' relationships' : '') });
}

function drawGraph(candidateNodeIds, candidateEdges, meta) {
  meta = meta || {};
  var previousInspectorState = currentView && currentView.inspectorState;
  var isNewView = !currentView || candidateNodeIds !== currentView.nodeIds || candidateEdges !== currentView.edges;
  if (!suppressHistory && currentView && isNewView) {
    viewHistory.push(currentView);
    if (viewHistory.length > 30) viewHistory.shift();
  }
  suppressHistory = false;
  currentView = { nodeIds: candidateNodeIds, edges: candidateEdges, meta: meta,
    inspectorState: isNewView ? null : previousInspectorState };
  if (isNewView) clearInspectorForView();
  byId('backViewBtn').disabled = viewHistory.length === 0;

  // Direction is meaningful only while its anchor belongs to this view. A new
  // query or navigation target should never appear blank because it inherited
  // an anchor from an unrelated view.
  if (edgeDirectionAnchorId && !candidateNodeIds.has(edgeDirectionAnchorId)) {
    if (selectedNodeId === edgeDirectionAnchorId) selectedNodeId = null;
    activeEdgeDirection = 'all';
    edgeDirectionAnchorId = null;
    updateEdgeDirectionControl();
    updateAppliedFilters();
  } else if (activeEdgeDirection !== 'all' && !edgeDirectionAnchorId) {
    activeEdgeDirection = 'all';
    updateEdgeDirectionControl();
    updateAppliedFilters();
  }

  function isPinned(id) {
    return id === meta.centerId ||
      (activeEdgeDirection !== 'all' && id === edgeDirectionAnchorId) ||
      (meta.pinnedIds && meta.pinnedIds.has(id));
  }
  var graphInk = getComputedStyle(document.documentElement).getPropertyValue('--ink').trim() || '#E8EBF1';

  var eligibleIds = new Set();
  candidateNodeIds.forEach(function (id) {
    var n = graph.nodes.get(id);
    if (!n) return;
    if ((isPinned(id) || activeKinds.has(n.kind)) && (!activeOwnedOnly || ownedNodeIds.has(id))) eligibleIds.add(id);
  });

  var visibleEdgeList = candidateEdges.filter(function (e) {
    var category = CAT_META[e.category] ? e.category : 'structural';
    return activeEdgeCategories.has(category) && activeEdgeKinds.has(e.kind || 'Unknown') &&
      edgePassesDirectionFilter(e) && eligibleIds.has(e.from) && eligibleIds.has(e.to);
  });

  var renderEdgeList = visibleEdgeList;
  if (groupParallelEdges) {
    var grouped = new Map();
    visibleEdgeList.forEach(function (e) {
      var key = edgeVariantKey(e);
      if (!grouped.has(key)) grouped.set(key, Object.assign({}, e, { groupedCount: 0, sourceEdges: [] }));
      var group = grouped.get(key);
      group.groupedCount++;
      group.sourceEdges.push(e);
    });
    renderEdgeList = Array.from(grouped.values());
  }

  // Only show nodes which still participate in a selected edge category. Query
  // targets and neighborhood centers stay visible to preserve navigation context.
  var visibleIds = new Set();
  visibleEdgeList.forEach(function (e) { visibleIds.add(e.from); visibleIds.add(e.to); });
  candidateNodeIds.forEach(function (id) {
    if (isPinned(id) && graph.nodes.has(id) && (!activeOwnedOnly || ownedNodeIds.has(id))) visibleIds.add(id);
  });

  var degree = new Map();
  renderEdgeList.forEach(function (e) {
    degree.set(e.from, (degree.get(e.from) || 0) + 1);
    degree.set(e.to, (degree.get(e.to) || 0) + 1);
  });

  var suffix = dominantDomainSuffix(visibleIds);
  var visNodes = [];
  visibleIds.forEach(function (id) {
    var n = graph.nodes.get(id);
    var km = KIND_META[n.kind] || KIND_META.Unknown;
    var pinned = isPinned(id);
    var owned = ownedNodeIds.has(id);
    var fullName = displayName(n);
    visNodes.push({
      id: id,
      shape: km.shape,
      label: shortLabel(fullName, suffix, 22),
      title: escapeHtml(fullName + (owned ? ' — Owned' : '')),
      font: { color: graphInk, size: 12 },
      color: {
        background: km.color,
        border: owned ? '#66D17A' : (n.highValue ? '#E8A33D' : km.color),
        highlight: { background: km.color, border: '#4FA3F7' }
      },
      borderWidth: (n.highValue || pinned || owned) ? 3 : 1,
      shapeProperties: n.isStub ? { borderDashes: [4, 3] } : {},
      size: pinned ? 26 : Math.max(10, Math.min(10 + (degree.get(id) || 0) * 1.4, 40))
    });
  });

  // Group edges by the (unordered) node pair they connect, so multiple distinct
  // relationships between the same two objects - common in AD data, e.g. a user
  // that's both AdminTo and HasSession on the same box - fan out into visibly
  // separate curves instead of drawing directly on top of one another.
  var pairGroups = new Map();
  visibleEdgeList.forEach(function (e) {
    var pair = [String(e.from), String(e.to)].sort();
    var key = JSON.stringify(pair);
    if (!pairGroups.has(key)) pairGroups.set(key, []);
    pairGroups.get(key).push(e);
  });
  var pairSeen = new Map();
  function smoothFor(e) {
    var pair = [String(e.from), String(e.to)].sort();
    var key = JSON.stringify(pair);
    var group = pairGroups.get(key);
    if (group.length <= 1) return { type: 'continuous' };
    var i = pairSeen.get(key) || 0;
    pairSeen.set(key, i + 1);
    var roundness = Math.min(0.15 + Math.floor(i / 2) * 0.12, 0.6);
    return { type: (i % 2 === 0) ? 'curvedCW' : 'curvedCCW', roundness: roundness };
  }

  var visEdges = [];
  currentVisEdgeMap = {};
  renderEdgeList.forEach(function (e, idx) {
    var cm = CAT_META[e.category] || CAT_META.structural;
    currentVisEdgeMap['e' + idx] = { edge: e, fromNode: graph.nodes.get(e.from), toNode: graph.nodes.get(e.to) };
    visEdges.push({
      id: 'e' + idx,
      from: e.from, to: e.to,
      color: { color: cm.color, highlight: '#4FA3F7' },
      width: e.category === 'structural' ? 1 : 2,
      arrows: { to: { enabled: true, scaleFactor: 0.5 } },
      smooth: smoothFor(e),
      dashes: !!e.inherited,
      label: e.groupedCount > 1 ? String(e.groupedCount) : undefined,
      title: escapeHtml(e.kind + (e.groupedCount > 1 ? ' (' + e.groupedCount + ' edges)' : ''))
    });
  });

  // Filtering the same logical view should not destroy the canvas, rebind all
  // handlers, and run another 400-iteration layout. Preserve known positions
  // and update the existing network with physics disabled.
  var reuseNetwork = !!(network && !isNewView);
  var existingPositions = reuseNetwork ? network.getPositions() : null;
  if (existingPositions) visNodes.forEach(function (node) {
    var position = existingPositions[node.id];
    if (position) { node.x = position.x; node.y = position.y; }
  });
  var data;
  if (reuseNetwork && currentNodeDataSet && currentEdgeDataSet) {
    var wantedNodeIds = new Set(visNodes.map(function (node) { return node.id; }));
    currentNodeDataSet.remove(currentNodeDataSet.getIds().filter(function (id) { return !wantedNodeIds.has(id); }));
    currentNodeDataSet.update(visNodes);
    currentEdgeDataSet.clear(); currentEdgeDataSet.add(visEdges);
    data = { nodes: currentNodeDataSet, edges: currentEdgeDataSet };
  } else {
    currentNodeDataSet = new vis.DataSet(visNodes); currentEdgeDataSet = new vis.DataSet(visEdges);
    data = { nodes: currentNodeDataSet, edges: currentEdgeDataSet };
  }
  var options = {
    autoResize: true,
    // Bind graph navigation to the canvas rather than the whole window. Global
    // bindings steal arrow/Home/End keys from the custom-query textarea.
    interaction: { hover: true, navigationButtons: false, keyboard: { enabled: true, bindToWindow: false }, multiselect: true },
    physics: {
      enabled: true,
      stabilization: { iterations: 400, fit: true },
      barnesHut: {
        gravitationalConstant: -8000,
        centralGravity: 0.15,
        springLength: 160,
        springConstant: 0.03,
        damping: 0.5,
        avoidOverlap: 0.9 // treats nodes as their real rendered size, not points - this is what actually stops overlap
      }
    },
    edges: { smooth: { type: 'continuous' } },
    nodes: { font: { color: graphInk } }
  };
  if (reuseNetwork) {
    network.setOptions({ physics: false });
  } else {
    if (network) network.destroy();
    network = new vis.Network(byId('canvas'), data, options);
    // run physics long enough to settle a genuinely new view, then freeze it
    network.once('stabilizationIterationsDone', function () {
      network.setOptions({ physics: false });
      network.fit();
    });
    network.on('click', function (p) {
      if (p.nodes.length) { selectNode(p.nodes[0]); }
      else if (p.edges.length) { selectEdge(p.edges[0]); }
    });
    network.on('doubleClick', function (p) {
      if (p.nodes.length) { selectNode(p.nodes[0]); openSelectiveExpand(p.nodes[0]); }
    });
  }
  if (selectedNodeId && visibleIds.has(selectedNodeId)) network.selectNodes([selectedNodeId]);

  updateGraphCaption(visibleIds.size, meta);
  byId('workspaceStatus').style.display = 'block';
  byId('workspaceStatus').textContent = visibleIds.size.toLocaleString() + ' nodes · ' + renderEdgeList.length.toLocaleString() +
    ' visible edges' + (groupParallelEdges && renderEdgeList.length !== visibleEdgeList.length ? ' · ' + visibleEdgeList.length.toLocaleString() + ' underlying' : '') +
    (activeEdgeDirection === 'in' ? ' · incoming only' : (activeEdgeDirection === 'out' ? ' · outgoing only' : ''));
}

function updateGraphCaption(shownCount, meta) {
  var el = byId('canvasCaption');
  if (meta.caption) {
    el.textContent = meta.caption;
  } else if (meta.centerId) {
    var c = graph.nodes.get(meta.centerId);
    el.textContent = 'Exploring ' + displayName(c) +
      (meta.capped ? ' — showing top ' + NEIGHBOR_CAP + ' of ' + meta.totalRelCount + ' relationships' : '');
  } else {
    el.textContent = 'Showing all ' + shownCount.toLocaleString() + ' objects';
  }
}
