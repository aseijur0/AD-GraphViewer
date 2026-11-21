// Extracted from NewOne/adCodex-cyberpunk.html; kept as a classic browser script.

// ---------------------------------------------------------------------------
// graph area state (empty / ready-but-blank / drawn)
// ---------------------------------------------------------------------------
function setGraphAreaState(state) {
  byId('emptyState').style.display = state === 'empty' ? 'flex' : 'none';
  byId('readyState').style.display = state === 'ready' ? 'flex' : 'none';
  var showGraph = state === 'graph';
  byId('canvas').style.display = showGraph ? 'block' : 'none';
  byId('canvasCaption').style.display = showGraph ? 'block' : 'none';
  byId('graphLegend').style.display = showGraph ? 'flex' : 'none';
}

// ---------------------------------------------------------------------------
// filter list (also doubles as the color legend)
// ---------------------------------------------------------------------------
function refreshFilterList() {
  var counts = {};
  KIND_ORDER.forEach(function (k) { counts[k] = 0; });
  graph.nodes.forEach(function (n) { counts[n.kind] = (counts[n.kind] || 0) + 1; });
  var present = KIND_ORDER.filter(function (k) { return counts[k] > 0; });
  var el = byId('filterList');
  if (!present.length) {
    el.innerHTML = '<div class="placeholder">Load data to see object types.</div>';
    byId('edgeSourceKind').innerHTML = '<option value="">Any source</option>';
    byId('edgeTargetKind').innerHTML = '<option value="">Any target</option>';
    return;
  }
  el.innerHTML = present.map(function (k) {
    var km = KIND_META[k];
    var checked = activeKinds.has(k) ? 'checked' : '';
    return '<label class="filterRow"><input type="checkbox" data-kind="' + k + '" ' + checked + '>' +
      '<span class="dot" style="background:' + km.color + '"></span>' +
      '<span class="fkName">' + k + '</span><span class="fkCount">' + counts[k] + '</span></label>';
  }).join('');
  var kindOptions = '<option value="">Any type</option>' + present.map(function (k) { return '<option value="' + k + '">' + k + '</option>'; }).join('');
  byId('edgeSourceKind').innerHTML = kindOptions.replace('Any type', 'Any source');
  byId('edgeTargetKind').innerHTML = kindOptions.replace('Any type', 'Any target');
}

function refreshRelationshipFilters() {
  Array.prototype.forEach.call(byId('relationshipFilters').querySelectorAll('input[data-category]'), function (input) {
    input.checked = activeEdgeCategories.has(input.getAttribute('data-category'));
  });
}

function refreshEdgeTypeFilters() {
  var counts = {};
  getGraphIndex().allEdges.forEach(function (e) { var k = e.kind || 'Unknown'; counts[k] = (counts[k] || 0) + 1; });
  availableEdgeKinds = Object.keys(counts).sort(function (a, b) { return a.localeCompare(b); });
  if (!edgeKindFiltersInitialized) {
    activeEdgeKinds = new Set(availableEdgeKinds);
    edgeKindFiltersInitialized = true;
  }
  var el = byId('edgeTypeFilterList');
  if (!availableEdgeKinds.length) { el.innerHTML = '<div class="placeholder">Load data to see edge types.</div>'; updateAppliedFilters(); return; }
  el.innerHTML = availableEdgeKinds.map(function (k) {
    return '<label class="filterRow"><input type="checkbox" data-edge-kind="' + escapeHtml(k) + '" ' + (activeEdgeKinds.has(k) ? 'checked' : '') + '>' +
      '<span class="fkName">' + escapeHtml(k) + '</span><span class="fkCount">' + counts[k] + '</span></label>';
  }).join('');
  updateAppliedFilters();
}

function updateAppliedFilters() {
  var chips = [];
  if (activeKinds.size !== KIND_ORDER.length) chips.push(activeKinds.size + '/' + KIND_ORDER.length + ' node types');
  if (activeEdgeCategories.size !== Object.keys(CAT_META).length) chips.push(activeEdgeCategories.size + '/' + Object.keys(CAT_META).length + ' edge categories');
  if (availableEdgeKinds.length && activeEdgeKinds.size !== availableEdgeKinds.length) chips.push(activeEdgeKinds.size + '/' + availableEdgeKinds.length + ' edge types');
  if (activeOwnedOnly) chips.push('Owned nodes only');
  if (activeEdgeDirection !== 'all' && edgeDirectionAnchorId) {
    var anchor = graph.nodes.get(edgeDirectionAnchorId);
    chips.push((activeEdgeDirection === 'in' ? 'Incoming to ' : 'Outgoing from ') + (anchor ? displayName(anchor) : edgeDirectionAnchorId));
  }
  byId('appliedFilters').innerHTML = chips.map(function (c) { return '<span class="filterChip">' + escapeHtml(c) + '</span>'; }).join('');
  saveWorkspacePreferences();
}

function updateEdgeDirectionControl() {
  var anchor = edgeDirectionAnchorId && graph.nodes.get(edgeDirectionAnchorId);
  var canFilter = !!anchor;
  var label = byId('edgeDirectionLabel');
  label.textContent = activeEdgeDirection === 'all' || !anchor
    ? 'Edges'
    : (activeEdgeDirection === 'in' ? 'Into: ' : 'From: ') + shortLabel(displayName(anchor), null, 18);
  label.title = anchor ? displayName(anchor) : 'Select an object to filter its relationships by direction';
  Array.prototype.forEach.call(byId('edgeDirectionControl').querySelectorAll('[data-edge-direction]'), function (button) {
    var direction = button.getAttribute('data-edge-direction');
    button.setAttribute('aria-pressed', direction === activeEdgeDirection ? 'true' : 'false');
    if (direction !== 'all') {
      button.disabled = !canFilter;
      button.title = !canFilter
        ? 'Select an object to show its ' + (direction === 'in' ? 'incoming' : 'outgoing') + ' relationships'
        : 'Show only relationships ' + (direction === 'in' ? 'entering ' : 'leaving ') + displayName(anchor);
    }
  });
}

function setEdgeDirection(direction) {
  if (['all', 'in', 'out'].indexOf(direction) === -1) return;
  if (direction !== 'all' && (!edgeDirectionAnchorId || !graph.nodes.has(edgeDirectionAnchorId))) {
    showToast('Select an object before filtering relationship direction.');
    return;
  }
  activeEdgeDirection = direction;
  updateEdgeDirectionControl();
  applyFilters();
}

function edgePassesDirectionFilter(edge) {
  if (activeEdgeDirection === 'all' || !edgeDirectionAnchorId) return true;
  return activeEdgeDirection === 'in'
    ? edge.to === edgeDirectionAnchorId
    : edge.from === edgeDirectionAnchorId;
}

function resetAllFilters(selected) {
  activeKinds = selected ? new Set(KIND_ORDER) : new Set();
  activeEdgeCategories = selected ? new Set(Object.keys(CAT_META)) : new Set();
  activeEdgeKinds = selected ? new Set(availableEdgeKinds) : new Set();
  edgeKindFiltersInitialized = true;
  activeOwnedOnly = false;
  activeEdgeDirection = 'all';
  byId('ownedOnlyFilter').checked = false;
  refreshFilterList(); refreshRelationshipFilters(); refreshEdgeTypeFilters(); updateEdgeDirectionControl(); applyFilters();
}

function refreshOwnedFilter() {
  var hasOwned = ownedNodeIds.size > 0;
  byId('ownedFilterRow').style.display = hasOwned ? 'flex' : 'none';
  byId('ownedCount').textContent = ownedNodeIds.size;
  if (!hasOwned) {
    activeOwnedOnly = false;
    byId('ownedOnlyFilter').checked = false;
  }
}

function toggleOwnedNode(id) {
  if (!graph.nodes.has(id)) return;
  if (ownedNodeIds.has(id)) ownedNodeIds.delete(id); else ownedNodeIds.add(id);
  refreshOwnedFilter();
  refreshSuggestedAttackPaths();
  applyFilters();
  if (graph.nodes.has(id)) selectNode(id);
}

function showOwnedNodesOnly(enabled) {
  activeOwnedOnly = enabled;
  updateAppliedFilters();
  if (enabled) {
    ownedFilterBaseView = currentView;
    setGraphAreaState('graph');
    drawGraph(new Set(graph.nodes.keys()), getGraphIndex().allEdges, { pinnedIds: new Set(ownedNodeIds), caption: 'Owned nodes' });
  } else if (ownedFilterBaseView) {
    var restore = ownedFilterBaseView, inspectorState = restore.inspectorState;
    ownedFilterBaseView = null; suppressHistory = true;
    drawGraph(restore.nodeIds, restore.edges, restore.meta);
    restoreInspectorState(inspectorState);
  } else if (currentView) {
    applyFilters();
  }
}

function applyFilters() {
  updateAppliedFilters();
  if (currentView) drawGraph(currentView.nodeIds, currentView.edges, currentView.meta);
}
