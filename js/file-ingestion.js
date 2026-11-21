// Extracted from NewOne/adCodex-cyberpunk.html; kept as a classic browser script.

// ---------------------------------------------------------------------------
// ingestion
// ---------------------------------------------------------------------------
var MAX_INPUT_FILE_BYTES = 512 * 1024 * 1024;
var MAX_ZIP_ENTRY_BYTES = 128 * 1024 * 1024;
var MAX_ZIP_TOTAL_BYTES = 512 * 1024 * 1024;
var MAX_ZIP_JSON_ENTRIES = 500;

function mergeParsedGraph(payload) {
  (payload.nodes || []).forEach(function (node) {
    if (node.isStub) ensureNode(graph, node.id, node.kind, node.properties);
    else upsertFullNode(graph, node.id, node.kind, node.properties);
  });
  (payload.edges || []).forEach(function (edge) {
    addEdge(graph, edge.from, edge.to, edge.kind, edge.category, edge);
  });
}

async function parseFilesInWorker(files) {
  var payload = [];
  for (var i = 0; i < files.length; i++) {
    if (files[i].size > MAX_INPUT_FILE_BYTES) throw new Error(files[i].name + ' exceeds the 512 MB safety limit');
    if (!/\.(json|zip)$/i.test(files[i].name)) { payload.push({ name: files[i].name, unsupported: true }); continue; }
    payload.push({ name: files[i].name, buffer: await files[i].arrayBuffer() });
  }
  return new Promise(function (resolve, reject) {
    var worker = new Worker('js/ingestion-worker.js');
    worker.onmessage = function (event) {
      worker.terminate();
      if (event.data.fatal) reject(new Error(event.data.fatal));
      else resolve(event.data);
    };
    worker.onerror = function (event) { worker.terminate(); reject(new Error(event.message || 'ingestion worker failed')); };
    worker.postMessage({ files: payload }, payload.filter(function (item) { return item.buffer; }).map(function (item) { return item.buffer; }));
  });
}

async function handleFiles(fileList) {
  document.body.setAttribute('aria-busy', 'true');
  byId('dropHint').textContent = 'Loading and parsing files…';
  var files = Array.prototype.slice.call(fileList);
  var results = [];
  if (typeof Worker !== 'undefined') {
    try {
      var workerResult = await parseFilesInWorker(files);
      mergeParsedGraph(workerResult);
      results = workerResult.results || [];
      afterIngest(results);
      document.body.removeAttribute('aria-busy');
      byId('dropHint').textContent = 'Drop SharpHound / AzureHound .json or .zip files anywhere on this page';
      return;
    } catch (workerError) {
      // file:// deployments and restrictive CSPs can block workers. The
      // existing parser remains a compatible fallback.
      console.warn('Worker ingestion unavailable; using main thread.', workerError);
    }
  }
  for (var i = 0; i < files.length; i++) {
    var f = files[i];
    if (f.size > MAX_INPUT_FILE_BYTES) {
      results.push({ filename: f.name, error: 'file exceeds the 512 MB safety limit' });
      continue;
    }
    if (/\.zip$/i.test(f.name)) {
      try {
        var buf = await f.arrayBuffer();
        var zip = await JSZip.loadAsync(buf);
        var names = Object.keys(zip.files);
        var jsonNames = names.filter(function (name) { return !zip.files[name].dir && /\.json$/i.test(name); });
        if (jsonNames.length > MAX_ZIP_JSON_ENTRIES) {
          results.push({ filename: f.name, error: 'archive contains more than ' + MAX_ZIP_JSON_ENTRIES + ' JSON files' });
          continue;
        }
        var expectedTotal = 0;
        var actualTotal = 0;
        for (var j = 0; j < names.length; j++) {
          var relPath = names[j];
          var entry = zip.files[relPath];
          if (entry.dir || !/\.json$/i.test(relPath)) continue;
          try {
            var expectedSize = entry._data && Number(entry._data.uncompressedSize || 0);
            if (expectedSize > MAX_ZIP_ENTRY_BYTES) throw new Error('uncompressed entry exceeds the 128 MB safety limit');
            expectedTotal += expectedSize;
            if (expectedTotal > MAX_ZIP_TOTAL_BYTES) throw new Error('archive exceeds the 512 MB uncompressed safety limit');
            var text = await entry.async('string');
            // String.length counts UTF-16 code units, not bytes. Blob.size
            // gives the real UTF-8 payload size for limits on JSON data.
            var actualSize = new Blob([text]).size;
            if (actualSize > MAX_ZIP_ENTRY_BYTES) throw new Error('uncompressed entry exceeds the 128 MB safety limit');
            actualTotal += actualSize;
            if (actualTotal > MAX_ZIP_TOTAL_BYTES) throw new Error('archive exceeds the 512 MB uncompressed safety limit');
            var json = JSON.parse(text);
            results.push(Object.assign({ filename: relPath }, ingestFile(graph, json, relPath)));
          } catch (err) {
            results.push({ filename: relPath, error: 'could not parse: ' + err.message });
          }
        }
      } catch (err2) {
        results.push({ filename: f.name, error: 'could not read zip: ' + err2.message });
      }
    } else if (/\.json$/i.test(f.name)) {
      try {
        var text2 = await f.text();
        var json2 = JSON.parse(text2);
        results.push(Object.assign({ filename: f.name }, ingestFile(graph, json2, f.name)));
      } catch (err3) {
        results.push({ filename: f.name, error: 'could not parse: ' + err3.message });
      }
    } else {
      results.push({ filename: f.name, error: 'not a .json or .zip file, skipped' });
    }
  }
  afterIngest(results);
  document.body.removeAttribute('aria-busy');
  byId('dropHint').textContent = 'Drop SharpHound / AzureHound .json or .zip files anywhere on this page';
}

function afterIngest(results) {
  // Some PKI hierarchy edges depend on objects delivered in different JSON
  // files, so resolve them only after the current upload batch is complete.
  reconcileADCSRelationships(graph);
  var errors = results.filter(function (r) { return r.error; });
  var summaryEl = byId('summaryLine');
  summaryEl.textContent = graph.nodes.size
    ? 'Loaded ' + graph.nodes.size.toLocaleString() + ' objects, ' + graph.edges.length.toLocaleString() + ' relationships' +
      (errors.length ? ' — ' + errors.length + ' file(s) had errors' : '')
    : 'No data loaded yet.';
  summaryEl.title = errors.length
    ? errors.map(function (e) { return e.filename + ': ' + e.error; }).join('\n')
    : '';
  if (errors.length) showToast(errors.length + ' file' + (errors.length === 1 ? '' : 's') + ' could not be loaded. See the dataset summary for details.');

  var hasData = graph.nodes.size > 0;
  byId('suggestedPathsSection').hidden = !hasData;
  byId('sidebar').classList.toggle('noData', !hasData);
  if (!hasData) byId('sidebar').classList.remove('mobileOpen');
  byId('inspectorMobileBtn').style.display = hasData ? '' : 'none';
  ownedNodeIds.forEach(function (id) { if (!graph.nodes.has(id)) ownedNodeIds.delete(id); });
  refreshOwnedFilter();

  refreshFilterList();
  refreshRelationshipFilters();
  edgeKindFiltersInitialized = false;
  refreshEdgeTypeFilters();
  renderQueryList();
  refreshEdgeKindOptions();

  // never leave a stale graph on screen after new data comes in - always land blank
  if (network) { network.destroy(); network = null; }
  currentView = null;
  ownedFilterBaseView = null;
  selectedNodeId = null;
  activeEdgeDirection = 'all';
  edgeDirectionAnchorId = null;
  currentVisEdgeMap = {};
  updateEdgeDirectionControl();
  byId('inspector').innerHTML = '<div class="placeholder">Select an object to see its details.</div>';
  hideFindingPanel();
  refreshSuggestedAttackPaths();

  if (graph.nodes.size === 0) {
    setGraphAreaState('empty');
  } else {
    setGraphAreaState('ready');
    byId('readyText').textContent = graph.nodes.size.toLocaleString() + ' objects, ' +
      graph.edges.length.toLocaleString() + ' relationships loaded. Run a query on the left, ' +
      'search for something specific, or:';
  }
}
