// Extracted from NewOne/adCodex-cyberpunk.html; kept as a classic browser script.

// ---------------------------------------------------------------------------
// wiring
// ---------------------------------------------------------------------------
byId('sampleBtn').addEventListener('click', loadSampleData);
byId('sampleBtn2').addEventListener('click', loadSampleData);

byId('clearBtn').addEventListener('click', function () {
  if (graph.nodes.size === 0) return;
  if (!confirm('Clear all loaded data?')) return;
  graph = makeGraph();
  activeKinds = new Set(KIND_ORDER);
  activeEdgeCategories = new Set(Object.keys(CAT_META));
  activeEdgeKinds = new Set(); edgeKindFiltersInitialized = false; viewHistory = [];
  ownedNodeIds = new Set(); activeOwnedOnly = false;
  ownedFilterBaseView = null;
  selectedNodeId = null;
  currentView = null;
  if (network) { network.destroy(); network = null; }
  byId('inspector').innerHTML = '<div class="placeholder">Select an object to see its details.</div>';
  byId('searchInput').value = '';
  byId('searchResults').style.display = 'none';
  afterIngest([]);
});

byId('fileInput').addEventListener('change', function (e) {
  if (e.target.files.length) handleFiles(e.target.files);
  e.target.value = '';
});

window.addEventListener('dragover', function (e) { e.preventDefault(); });
window.addEventListener('dragenter', function () { document.body.classList.add('dragging'); });
window.addEventListener('dragleave', function (e) { if (!e.relatedTarget) document.body.classList.remove('dragging'); });
window.addEventListener('drop', function (e) {
  e.preventDefault();
  document.body.classList.remove('dragging');
  if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
});

byId('showFullBtn').addEventListener('click', function () {
  if (graph.nodes.size > CONFIRM_HUGE_THRESHOLD) {
    var ok = confirm('This will render ' + graph.nodes.size.toLocaleString() + ' objects and ' +
      graph.edges.length.toLocaleString() + ' relationships at once, which may be slow on this dataset. Continue?');
    if (!ok) return;
  }
  renderFullGraph();
});

byId('searchInput').addEventListener('input', debounce(function (e) { runSearch(e.target.value); }, 150));

byId('searchResults').addEventListener('click', function (e) {
  var row = e.target.closest('.searchRow');
  if (!row) return;
  var id = row.getAttribute('data-id');
  showNeighborhood(id);
  selectNode(id);
  byId('searchInput').value = '';
  byId('searchResults').style.display = 'none';
});

byId('inspector').addEventListener('click', function (e) {
  var guidanceBtn = e.target.closest('[data-guidance-path]');
  if (guidanceBtn) { renderGuidancePath(guidanceBtn.getAttribute('data-guidance-path')); return; }
  var ownedBtn = e.target.closest('[data-owned-id]');
  if (ownedBtn) { toggleOwnedNode(ownedBtn.getAttribute('data-owned-id')); return; }
  var row = e.target.closest('.relRow');
  if (!row) return;
  var id = row.getAttribute('data-id');
  showNeighborhood(id);
  selectNode(id);
});

byId('findingPanel').addEventListener('click', function (e) {
  if (e.target.closest('.findingClose')) { hideFindingPanel(); return; }

  var tabBtn = e.target.closest('.findingTab');
  if (tabBtn) {
    var os = tabBtn.getAttribute('data-os');
    var panel = byId('findingPanel');
    Array.prototype.forEach.call(panel.querySelectorAll('.findingTab'), function (b) {
      b.classList.toggle('active', b === tabBtn);
    });
    Array.prototype.forEach.call(panel.querySelectorAll('.findingCmdGroup'), function (g) {
      g.style.display = (g.getAttribute('data-os') === os) ? 'block' : 'none';
    });
    return;
  }

  var copyBtn = e.target.closest('.findingCopyBtn');
  if (copyBtn) { copyFindingCmd(copyBtn); return; }
});

byId('filterList').addEventListener('change', function (e) {
  if (e.target.type !== 'checkbox') return;
  var kind = e.target.getAttribute('data-kind');
  if (e.target.checked) activeKinds.add(kind); else activeKinds.delete(kind);
  applyFilters();
});

byId('relationshipFilters').addEventListener('change', function (e) {
  if (e.target.type !== 'checkbox') return;
  var category = e.target.getAttribute('data-category');
  if (e.target.checked) activeEdgeCategories.add(category); else activeEdgeCategories.delete(category);
  applyFilters();
});

byId('edgeTypeFilterList').addEventListener('change', function (e) {
  if (e.target.type !== 'checkbox') return;
  var kind = e.target.getAttribute('data-edge-kind');
  if (e.target.checked) activeEdgeKinds.add(kind); else activeEdgeKinds.delete(kind);
  applyFilters();
});

byId('selectAllFiltersBtn').addEventListener('click', function () { resetAllFilters(true); });
byId('clearFiltersBtn').addEventListener('click', function () { resetAllFilters(false); });
byId('resetFiltersBtn').addEventListener('click', function () { resetAllFilters(true); });
byId('ownedOnlyFilter').addEventListener('change', function (e) { showOwnedNodesOnly(e.target.checked); });
byId('edgeDirectionControl').addEventListener('click', function (e) {
  var button = e.target.closest('[data-edge-direction]');
  if (!button || button.disabled) return;
  setEdgeDirection(button.getAttribute('data-edge-direction'));
});

byId('queryToggle').addEventListener('click', function () {
  setExplorerOpen(byId('queryPanel').classList.contains('panelHidden'));
});

byId('queryList').addEventListener('change', function (e) {
  var qdef = PREMADE_QUERIES.find(function (q) { return q.id === e.target.value; });
  if (qdef) runQuery(qdef);
});

byId('suggestedPathList').addEventListener('click', function (e) {
  var card = e.target.closest('[data-suggested-path]');
  if (card) renderGuidancePath(card.getAttribute('data-suggested-path'));
});
byId('refreshSuggestedPathsBtn').addEventListener('click', refreshSuggestedAttackPaths);
['pathTargetMode', 'pathOptimizeMode', 'pathMaxHops', 'pathAllowSessions',
  'pathAllowInherited', 'pathAllowCrossDomain', 'pathOwnedOnly'].forEach(function (id) {
  byId(id).addEventListener('change', function () {
    refreshSuggestedAttackPaths();
    if (selectedNodeId && graph.nodes.has(selectedNodeId)) selectNode(selectedNodeId);
  });
});

byId('runEdgeQueryBtn').addEventListener('click', function () { runEdgeQuery(byId('edgeQueryInput').value); });
byId('clearEdgeQueryBtn').addEventListener('click', function () { byId('edgeQueryInput').value = ''; runEdgeQuery(''); });
byId('edgeQueryInput').addEventListener('keydown', function (e) { if (e.key === 'Enter') runEdgeQuery(e.target.value); });
byId('runCustomQueryBtn').addEventListener('click', function () { runCustomQuery(byId('customQueryInput').value); });
byId('clearCustomQueryBtn').addEventListener('click', function () {
  byId('customQueryInput').value = '';
  byId('customQueryStatus').textContent = '';
  byId('customQueryStatus').classList.remove('queryError');
  byId('customQueryInput').focus();
});
byId('customQueryInput').addEventListener('keydown', function (e) {
  // vis-network installs document-level keyboard navigation handlers. Keep
  // editing/navigation keys inside the textarea so arrows, Home/End, selection,
  // undo, and pasted-text editing behave like a normal text editor.
  e.stopPropagation();
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runCustomQuery(e.target.value); }
});
byId('customQueryInput').addEventListener('keyup', function (e) { e.stopPropagation(); });

byId('backViewBtn').addEventListener('click', goBackView);
byId('fitBtn').addEventListener('click', function () { if (network) network.fit({ animation: true }); });
byId('zoomInBtn').addEventListener('click', function () { if (network) network.moveTo({ scale: network.getScale() * 1.25, animation: true }); });
byId('zoomOutBtn').addEventListener('click', function () { if (network) network.moveTo({ scale: network.getScale() / 1.25, animation: true }); });
byId('layoutBtn').addEventListener('click', function () { if (network) { physicsFrozen = false; network.setOptions({ physics: true }); network.stabilize(300); updatePhysicsButton(); } });
byId('freezeBtn').addEventListener('click', function () { if (!network) return; physicsFrozen = !physicsFrozen; network.setOptions({ physics: !physicsFrozen }); updatePhysicsButton(); });
byId('isolateBtn').addEventListener('click', isolateSelection);
byId('pathBtn').addEventListener('click', shortestPathSelection);
byId('hideSelectedBtn').addEventListener('click', hideSelection);
byId('groupEdgesBtn').addEventListener('click', function () { groupParallelEdges = !groupParallelEdges; updateGroupEdgesButton(); saveWorkspacePreferences(); applyFilters(); });
byId('clearSceneBtn').addEventListener('click', clearScene);
byId('fullscreenBtn').addEventListener('click', function () { if (!document.fullscreenElement) byId('graphArea').requestFullscreen(); else document.exitFullscreen(); });
byId('exportBtn').addEventListener('click', exportCurrentView);
byId('runExpandBtn').addEventListener('click', runSelectiveExpand);
byId('cancelExpandBtn').addEventListener('click', function () { byId('expandPanel').style.display = 'none'; });
byId('inspectorMobileBtn').addEventListener('click', function () { byId('sidebar').classList.toggle('mobileOpen'); byId('queryPanel').classList.remove('mobileOpen'); });
byId('closeInspectorBtn').addEventListener('click', function () { byId('sidebar').classList.remove('mobileOpen'); });
byId('themeToggle').addEventListener('click', function () { applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light'); });
byId('edgeTypeFilterSearch').addEventListener('input', function (e) {
  var q = e.target.value.trim().toLowerCase();
  Array.prototype.forEach.call(byId('edgeTypeFilterList').querySelectorAll('.filterRow'), function (row) {
    row.style.display = !q || row.textContent.toLowerCase().indexOf(q) !== -1 ? 'flex' : 'none';
  });
});
window.addEventListener('keydown', function (e) {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault(); setExplorerOpen(true); byId('searchInput').closest('details').open = true; byId('searchInput').focus();
  } else if (e.key === 'Escape') {
    byId('expandPanel').style.display = 'none'; hideFindingPanel();
  }
});

restoreTheme();
restoreWorkspacePreferences();
updatePhysicsButton();
updateEdgeDirectionControl();
if (window.ResizeObserver) {
  var workspaceResizeObserver = new ResizeObserver(debounce(function () { positionExplorerToggle(); saveWorkspacePreferences(); }, 250));
  workspaceResizeObserver.observe(byId('queryPanel')); workspaceResizeObserver.observe(byId('sidebar'));
}

renderQueryList();
setGraphAreaState('empty');
