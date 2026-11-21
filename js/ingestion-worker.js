// Off-main-thread BloodHound parsing. This worker deliberately returns plain
// arrays so the main thread can merge a batch into an existing in-memory graph.
importScripts('vendor/jszip.min.js', 'bloodhound-parser.js');

var WORKER_ENTRY_LIMIT = 128 * 1024 * 1024;
var WORKER_TOTAL_LIMIT = 512 * 1024 * 1024;

self.onmessage = async function (event) {
  var files = event.data.files || [], workerGraph = makeGraph(), results = [];
  try {
    for (var i = 0; i < files.length; i++) {
      var file = files[i];
      if (file.unsupported) { results.push({ filename: file.name, error: 'not a .json or .zip file, skipped' }); continue; }
      if (/\.zip$/i.test(file.name)) {
        var zip = await JSZip.loadAsync(file.buffer), names = Object.keys(zip.files), total = 0;
        var jsonCount = names.filter(function (name) { return !zip.files[name].dir && /\.json$/i.test(name); }).length;
        if (jsonCount > 500) throw new Error('archive contains more than 500 JSON files');
        for (var j = 0; j < names.length; j++) {
          var name = names[j], entry = zip.files[name];
          if (entry.dir || !/\.json$/i.test(name)) continue;
          var expected = entry._data && Number(entry._data.uncompressedSize || 0);
          if (expected > WORKER_ENTRY_LIMIT || total + expected > WORKER_TOTAL_LIMIT) throw new Error('archive exceeds an uncompressed safety limit');
          var text = await entry.async('string'); total += new Blob([text]).size;
          if (total > WORKER_TOTAL_LIMIT) throw new Error('archive exceeds the 512 MB uncompressed safety limit');
          results.push(Object.assign({ filename: name }, ingestFile(workerGraph, JSON.parse(text), name)));
        }
      } else {
        var decoded = new TextDecoder().decode(file.buffer);
        results.push(Object.assign({ filename: file.name }, ingestFile(workerGraph, JSON.parse(decoded), file.name)));
      }
    }
    reconcileADCSRelationships(workerGraph);
    self.postMessage({ nodes: Array.from(workerGraph.nodes.values()), edges: workerGraph.edges, results: results });
  } catch (error) {
    self.postMessage({ fatal: error.message || String(error) });
  }
};
