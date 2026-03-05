/**
 * dataParser.js — Parses vulnerability report JSON and outputs a
 * normalised structure for rendering.
 *
 * Supports TWO report formats:
 *
 *   1. OWASP format (dependency-check-report.json)
 *      Top-level `dependencies[]`, each with nested `vulnerabilities[]`.
 *      Rich data: CVSS scores, CWE, vulnerable software ranges, etc.
 *
 *   2. GitLab format (dependency-check-gitlab.json)
 *      Top-level `vulnerabilities[]`, each with `location.dependency`.
 *      Limited fields (often no score, no CWE).
 *
 * The parser auto-detects the format and normalises both into:
 *   {
 *     repo, severity, maxScore, totalDeps, totalCves,
 *     dependencies: [{
 *       name, version, severity, maxScore, fixVersion, hasExploit,
 *       cves: [{ id, severity, score, description, cwe,
 *                affectedVersions, fixedIn, url, hasExploit }]
 *     }]
 *   }
 */

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Parse a report JSON (auto-detects format).
 * @param {string} repoName  - display name for the repo
 * @param {object} json      - parsed JSON report
 * @returns {object}         - normalised repo object
 */
function parseReport(repoName, json) {
  var dependencies;

  // Detect format: OWASP has top-level `dependencies[]`,
  // GitLab has top-level `vulnerabilities[]`
  if (json.dependencies && Array.isArray(json.dependencies)) {
    dependencies = parseOwaspFormat(json);
  } else {
    dependencies = parseGitlabFormat(json);
  }

  // Sort dependencies (spec: severity desc -> score desc -> name A-Z)
  sortDependencies(dependencies);

  // Compute repo-level summary
  var repoSeverity = 'unknown';
  var repoMaxScore = null;
  var totalCves = 0;

  dependencies.forEach(function (d) {
    if (SEVERITY_RANK[d.severity] > SEVERITY_RANK[repoSeverity]) {
      repoSeverity = d.severity;
    }
    if (d.maxScore !== null && (repoMaxScore === null || d.maxScore > repoMaxScore)) {
      repoMaxScore = d.maxScore;
    }
    totalCves += d.cves.length;
  });

  return {
    repo:         repoName,
    severity:     repoSeverity,
    maxScore:     repoMaxScore,
    totalDeps:    dependencies.length,
    totalCves:    totalCves,
    dependencies: dependencies
  };
}


// ---------------------------------------------------------------------------
// Format 1: OWASP dependency-check-report.json
// ---------------------------------------------------------------------------

function parseOwaspFormat(json) {
  var deps = json.dependencies || [];

  return deps
    .filter(function (dep) {
      return dep.vulnerabilities && dep.vulnerabilities.length > 0;
    })
    .map(function (dep) {
      var name = dep.fileName || 'Unknown';
      var version = '';

      // Extract version from packages array
      // e.g. "pkg:maven/com.itextpdf/barcodes@8.0.2"
      if (dep.packages && dep.packages.length) {
        var pkgId = dep.packages[0].id || '';
        var atIdx = pkgId.indexOf('@');
        if (atIdx !== -1) version = pkgId.substring(atIdx + 1);
      }
      if (!version && dep.version) version = dep.version;

      // Parse CVEs
      var cves = dep.vulnerabilities.map(function (v) {
        return parseCveOwasp(v);
      });

      sortCves(cves);
      return buildDepObject(name, version, cves);
    });
}

/** Parse a single CVE from OWASP format (rich data). */
function parseCveOwasp(v) {
  var severity = normalizeSeverity(v.severity);

  // Score: prefer cvssv3, fall back to cvssv2
  var score = null;
  if (v.cvssv3 && v.cvssv3.baseScore != null) {
    score = Number(v.cvssv3.baseScore);
    // Use the more precise baseSeverity from cvssv3 if available
    if (v.cvssv3.baseSeverity) severity = normalizeSeverity(v.cvssv3.baseSeverity);
  } else if (v.cvssv2 && v.cvssv2.score != null) {
    score = Number(v.cvssv2.score);
  }

  // CWE - array of strings like ["CWE-129", "NVD-CWE-noinfo"]
  var cwe = '\u2013';
  if (v.cwes && v.cwes.length) {
    // Filter out NVD-CWE-noinfo/Other as they're not real CWEs
    var realCwes = v.cwes.filter(function (c) {
      return String(c).startsWith('CWE-');
    });
    if (realCwes.length) cwe = realCwes.join(', ');
    else cwe = v.cwes[0];
  }

  // Affected versions from vulnerableSoftware
  var affected = '\u2013';
  if (v.vulnerableSoftware && v.vulnerableSoftware.length) {
    var ranges = v.vulnerableSoftware
      .map(function (vs) {
        var sw = vs.software || vs;
        var parts = [];
        if (sw.versionStartIncluding) parts.push('>=' + sw.versionStartIncluding);
        if (sw.versionEndExcluding)   parts.push('<' + sw.versionEndExcluding);
        if (sw.versionEndIncluding)   parts.push('<=' + sw.versionEndIncluding);
        return parts.length ? parts.join(' ') : null;
      })
      .filter(Boolean);
    if (ranges.length) affected = ranges.join('; ');
  }

  // Fixed-in version (derived from versionEndExcluding)
  var fixedIn = '\u2013';
  if (v.vulnerableSoftware && v.vulnerableSoftware.length) {
    var fixVersions = v.vulnerableSoftware
      .map(function (vs) { return (vs.software || vs).versionEndExcluding || null; })
      .filter(Boolean);
    if (fixVersions.length) fixedIn = fixVersions.join(', ');
  }

  // URL
  var url = buildCveUrl(v.name);

  // Exploit detection - check references for "EXPLOIT" in name field
  var hasExploit = false;
  var refs = v.references || [];
  for (var i = 0; i < refs.length; i++) {
    var refName = refs[i].name || '';
    if (refName.toUpperCase().indexOf('EXPLOIT') !== -1) {
      hasExploit = true;
      break;
    }
  }

  return {
    id:               v.name || '\u2013',
    severity:         severity,
    score:            score,
    description:      v.description || '\u2013',
    cwe:              cwe,
    affectedVersions: affected,
    fixedIn:          fixedIn,
    url:              url,
    hasExploit:       hasExploit
  };
}


// ---------------------------------------------------------------------------
// Format 2: GitLab dependency-check-gitlab.json
// ---------------------------------------------------------------------------

function parseGitlabFormat(json) {
  var vulns = json.vulnerabilities || [];
  var depMap = {};

  vulns.forEach(function (v) {
    var loc  = v.location || {};
    var dep  = loc.dependency || {};
    var pkg  = dep.package || {};
    var name = pkg.name || loc.file || 'Unknown';
    var ver  = dep.version || '';
    var key  = name + '@' + ver;

    if (!depMap[key]) {
      depMap[key] = { name: name, version: ver, cves: [] };
    }

    depMap[key].cves.push(parseCveGitlab(v));
  });

  return Object.keys(depMap).map(function (key) {
    var dep = depMap[key];
    sortCves(dep.cves);
    return buildDepObject(dep.name, dep.version, dep.cves);
  });
}

/** Parse a single CVE from GitLab format (limited data). */
function parseCveGitlab(v) {
  var severity = normalizeSeverity(v.severity);

  var score = null;
  if (v.cvssScore != null)                          score = Number(v.cvssScore);
  else if (v.cvssv3 && v.cvssv3.baseScore != null)  score = Number(v.cvssv3.baseScore);
  else if (v.score != null)                          score = Number(v.score);

  var cwe = '\u2013';
  if (v.cwes && v.cwes.length)  cwe = v.cwes.join(', ');
  else if (v.cwe)               cwe = v.cwe;

  var url = null;
  var ids = v.identifiers || [];
  if (ids.length && ids[0].url) {
    url = ids[0].url;
  } else {
    url = buildCveUrl(v.name || v.id);
  }

  // Exploit detection from links
  var hasExploit = false;
  var links = v.links || [];
  for (var i = 0; i < links.length; i++) {
    if (links[i].name && links[i].name.indexOf('EXPLOIT') !== -1) {
      hasExploit = true;
      break;
    }
  }

  return {
    id:               v.name || v.id || '\u2013',
    severity:         severity,
    score:            score,
    description:      v.description || '\u2013',
    cwe:              cwe,
    affectedVersions: '\u2013',
    fixedIn:          '\u2013',
    url:              url,
    hasExploit:       hasExploit
  };
}


// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/**
 * Build a normalised dependency object from parsed CVEs.
 */
function buildDepObject(name, version, cves) {
  var depSeverity   = 'unknown';
  var depMaxScore   = null;
  var depHasExploit = false;

  cves.forEach(function (c) {
    if (SEVERITY_RANK[c.severity] > SEVERITY_RANK[depSeverity]) {
      depSeverity = c.severity;
    }
    if (c.score !== null && (depMaxScore === null || c.score > depMaxScore)) {
      depMaxScore = c.score;
    }
    if (c.hasExploit) depHasExploit = true;
  });

  return {
    name:       name,
    version:    version || '\u2013',
    severity:   depSeverity,
    maxScore:   depMaxScore,
    fixVersion: computeFixVersion(cves),
    hasExploit: depHasExploit,
    cves:       cves
  };
}

/**
 * Compute the best fix version for a dependency:
 * the highest fixedIn version across all its CVEs.
 */
function computeFixVersion(cves) {
  var versions = [];
  cves.forEach(function (c) {
    if (c.fixedIn && c.fixedIn !== '\u2013') {
      c.fixedIn.split(',').forEach(function (v) {
        var trimmed = v.trim();
        if (trimmed) versions.push(trimmed);
      });
    }
  });
  if (!versions.length) return '\u2013';

  versions.sort(function (a, b) { return compareSemver(b, a); });
  return versions[0];
}