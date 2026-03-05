/**
 * utils.js — Shared constants and helper functions.
 */

/** Severity ranking used for sorting (higher = more severe). */
var SEVERITY_RANK = {
  critical: 4,
  high:     3,
  medium:   2,
  low:      1,
  unknown:  0
};

/** Normalise severity strings from report data. */
function normalizeSeverity(raw) {
  if (!raw) return 'unknown';
  var s = String(raw).toLowerCase().trim();
  if (s === 'critical') return 'critical';
  if (s === 'high')     return 'high';
  if (s === 'medium' || s === 'moderate') return 'medium';
  if (s === 'low')      return 'low';
  return 'unknown';
}

/** Escape a string for safe HTML insertion. Returns a dash for null/undefined. */
function esc(value) {
  if (value == null || value === '') return '&#8211;';
  var el = document.createElement('span');
  el.textContent = String(value);
  return el.innerHTML;
}

/** Escape a string for use inside an HTML attribute value. */
function escAttr(value) {
  if (value == null || value === '') return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Basic semver-ish comparison.
 * Returns positive if a > b, negative if a < b, 0 if equal.
 */
function compareSemver(a, b) {
  var pa = String(a).split(/[.\-]/);
  var pb = String(b).split(/[.\-]/);
  for (var i = 0; i < Math.max(pa.length, pb.length); i++) {
    var na = parseInt(pa[i], 10) || 0;
    var nb = parseInt(pb[i], 10) || 0;
    if (na !== nb) return na - nb;
  }
  return 0;
}

/** Build an NVD / GitHub Advisory link for a CVE identifier. */
function buildCveUrl(id) {
  if (!id || id === '\u2013') return null;
  if (id.startsWith('CVE-'))  return 'https://nvd.nist.gov/vuln/detail/' + id;
  if (id.startsWith('GHSA-')) return 'https://github.com/advisories/' + id;
  return null;
}

/** Strip basic markdown formatting from a string. */
function stripMarkdown(text) {
  if (!text) return '';
  return String(text)
    .replace(/^#{1,6}\s*/gm, '')
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/\*(.+?)\*/g, '$1')
    .replace(/`(.+?)`/g, '$1')
    .replace(/\[(.+?)\]\(.+?\)/g, '$1')
    .trim();
}

/** Small right-pointing chevron SVG. */
function chevronSVG() {
  return '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M6 3l5 5-5 5z"/></svg>';
}