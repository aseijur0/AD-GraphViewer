// Extracted from NewOne/adCodex-cyberpunk.html; kept as a classic browser script.

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, function (c) {
    return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c];
  });
}

function formatPropValue(key, val) {
  if (typeof val === 'number' && /lastlogon|pwdlastset|whencreated|lastseen|firstseen/i.test(key)) {
    if (val === 0) return 'never';
    if (val < 0) return 'unknown';
    var d = new Date(val * 1000);
    if (d.getFullYear() > 1975 && d.getFullYear() < 2100) {
      return d.toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
    }
  }
  if (Array.isArray(val)) return val.length ? val.join(', ') : '(empty)';
  if (typeof val === 'boolean') return val ? 'true' : 'false';
  return String(val);
}

function debounce(fn, ms) {
  var t;
  return function () {
    var args = arguments;
    clearTimeout(t);
    t = setTimeout(function () { fn.apply(null, args); }, ms);
  };
}

// If most visible nodes share the same "@DOMAIN" suffix (the normal case for a
// single-domain view), stripping it shortens almost every label on screen for
// free. Nodes without that exact suffix (a Domain object, a different domain in
// a trust view, a bare-SID stub) are simply left alone.
function dominantDomainSuffix(nodeIds) {
  var counts = {};
  nodeIds.forEach(function (id) {
    var n = graph.nodes.get(id);
    if (!n) return;
    var name = displayName(n);
    var at = name.lastIndexOf('@');
    if (at === -1) return;
    var suffix = name.slice(at);
    counts[suffix] = (counts[suffix] || 0) + 1;
  });
  var best = null, bestCount = 1;
  Object.keys(counts).forEach(function (s) { if (counts[s] >= bestCount) { best = s; bestCount = counts[s]; } });
  return bestCount >= 2 ? best : null;
}

function shortLabel(fullName, suffix, maxLen) {
  var s = (suffix && fullName.slice(-suffix.length) === suffix) ? fullName.slice(0, -suffix.length) : fullName;
  if (s.length > maxLen) s = s.slice(0, maxLen - 1) + '\u2026';
  return s;
}

function byId(id) { return document.getElementById(id); }

var toastTimer = null;
function showToast(message) {
  var toast = byId('toast');
  toast.textContent = message;
  toast.style.opacity = '1'; toast.style.transform = 'translate(-50%,0)';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function () { toast.style.opacity = '0'; toast.style.transform = 'translate(-50%,16px)'; }, 2600);
}

function applyTheme(theme, persist) {
  document.documentElement.setAttribute('data-theme', theme);
  var button = byId('themeToggle'), light = theme === 'light';
  button.innerHTML = light ? '&#9790;' : '&#9788;';
  button.setAttribute('aria-label', light ? 'Switch to dark mode' : 'Switch to light mode');
  button.title = light ? 'Switch to dark mode' : 'Switch to light mode';
  if (persist !== false) { try { localStorage.setItem('adGraphTheme', theme); } catch (_) {} }
  if (currentView) drawGraph(currentView.nodeIds, currentView.edges, currentView.meta);
}

function restoreTheme() {
  var theme = 'dark';
  try { theme = localStorage.getItem('adGraphTheme') || ((window.matchMedia && window.matchMedia('(prefers-color-scheme:light)').matches) ? 'light' : 'dark'); } catch (_) {}
  applyTheme(theme, false);
}
