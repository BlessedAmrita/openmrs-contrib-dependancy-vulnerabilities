/**
 * renderer.js — Builds the DOM for the vulnerability dashboard
 * and wires up accordion toggle behaviour.
 */

/** Render the full dashboard into the target element. */
function renderDashboard(repos, targetId) {
  var container = document.getElementById(targetId);
  if (!container) return;

  sortRepos(repos);

  var html = '';
  repos.forEach(function (repo, ri) {
    html += buildRepoSection(repo, ri);
  });
  container.innerHTML = html;

  // Wire up accordion toggles
  attachToggles(container);
}


// ---------------------------------------------------------------------------
// Repo-level
// ---------------------------------------------------------------------------

function buildRepoSection(repo, repoIdx) {
  var id = 'repo-' + repoIdx;
  return (
    '<div class="repo-section">' +
      '<div class="repo-header" data-target="' + id + '">' +
        '<span class="chevron">' + chevronSVG() + '</span>' +
        '<span class="repo-name">' + esc(repo.repo) + '</span>' +
        severityPill(repo.severity) +
      '</div>' +
      '<div class="repo-body" id="' + id + '">' +
        buildDepTable(repo.dependencies, repoIdx) +
      '</div>' +
    '</div>'
  );
}


// ---------------------------------------------------------------------------
// Dependency table
// ---------------------------------------------------------------------------

function buildDepTable(deps, repoIdx) {
  var html =
    '<table class="dep-table">' +
      '<thead><tr>' +
        '<th></th>' +
        '<th>Dependency</th>' +
        '<th>Version</th>' +
        '<th>Severity <span class="sort-arrow">&#9660;</span></th>' +
        '<th>CVEs</th>' +
        '<th>Exploit?</th>' +
        '<th>Fix Version</th>' +
      '</tr></thead>' +
      '<tbody>';

  deps.forEach(function (dep, di) {
    var depId = 'dep-' + repoIdx + '-' + di;
    html += buildDepRow(dep, depId);
    html += buildCvePanel(dep.cves, depId);
  });

  html += '</tbody></table>';
  return html;
}


function buildDepRow(dep, depId) {
  return (
    '<tr class="dep-row" data-target="cve-panel-' + depId + '">' +
      '<td><span class="dep-chevron">' + chevronSVG() + '</span></td>' +
      '<td>' + esc(dep.name) + '</td>' +
      '<td>' + esc(dep.version) + '</td>' +
      '<td>' + severityPill(dep.severity) + '</td>' +
      '<td>' + dep.cves.length + '</td>' +
      '<td>' + (dep.hasExploit ? '<span style="color:#da1e28;font-weight:600">Yes</span>' : 'No') + '</td>' +
      '<td>' + esc(dep.fixVersion) + '</td>' +
    '</tr>'
  );
}


// ---------------------------------------------------------------------------
// CVE detail panel
// ---------------------------------------------------------------------------

/** The expandable CVE detail panel (hidden by default). */
function buildCvePanel(cves, depId) {
  return (
    '<tr class="cve-panel" id="cve-panel-' + depId + '">' +
      '<td colspan="7">' +
        '<div class="cve-scroll">' +
          '<table class="cve-table">' +
            buildCveTableHead() +
            '<tbody>' + buildCveRows(cves) + '</tbody>' +
          '</table>' +
        '</div>' +
      '</td>' +
    '</tr>'
  );
}

function buildCveTableHead() {
  return (
    '<thead><tr>' +
      '<th>CVE ID</th>' +
      '<th>Severity</th>' +
      '<th>Score</th>' +
      '<th>Description</th>' +
      '<th>Affected Versions</th>' +
      '<th>Fixed In</th>' +
      '<th>CWE</th>' +
    '</tr></thead>'
  );
}

function buildCveRows(cves) {
  var html = '';
  cves.forEach(function (cve) {
    var scoreStr = cve.score != null ? cve.score.toFixed(1) + '/10' : '&#8211;';
    var idCell = cve.url
      ? '<a class="cve-link" href="' + escAttr(cve.url) + '" target="_blank" rel="noopener">' + esc(cve.id) + '</a>'
      : esc(cve.id);

    var desc = stripMarkdown(cve.description);

    html +=
      '<tr>' +
        '<td>' + idCell + '</td>' +
        '<td>' + severityPill(cve.severity) + '</td>' +
        '<td class="score">' + scoreStr + '</td>' +
        '<td class="desc-cell" title="' + escAttr(desc) + '">' + esc(desc) + '</td>' +
        '<td class="affected-cell" title="' + escAttr(cve.affectedVersions) + '">' + esc(cve.affectedVersions) + '</td>' +
        '<td class="fixed-cell" title="' + escAttr(cve.fixedIn) + '">' + esc(cve.fixedIn) + '</td>' +
        '<td>' + esc(cve.cwe) + '</td>' +
      '</tr>';
  });
  return html;
}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function severityPill(severity) {
  var s = severity || 'unknown';
  return '<span class="pill pill-' + s + '">' + s.charAt(0).toUpperCase() + s.slice(1) + '</span>';
}


// ---------------------------------------------------------------------------
// Accordion toggle behaviour
// ---------------------------------------------------------------------------

function attachToggles(container) {
  // Repo headers
  var repoHeaders = container.querySelectorAll('.repo-header');
  repoHeaders.forEach(function (header) {
    header.addEventListener('click', function () {
      var targetId = header.getAttribute('data-target');
      var body = document.getElementById(targetId);
      if (!body) return;
      header.classList.toggle('open');
      body.classList.toggle('open');
    });
  });

  // Dependency rows
  var depRows = container.querySelectorAll('.dep-row');
  depRows.forEach(function (row) {
    row.addEventListener('click', function () {
      var targetId = row.getAttribute('data-target');
      var panel = document.getElementById(targetId);
      if (!panel) return;
      row.classList.toggle('open');
      panel.classList.toggle('open');
    });
  });
}