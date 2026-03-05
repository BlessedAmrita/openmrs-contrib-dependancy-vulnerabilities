/**
 * sorting.js — Comparators for repos, dependencies, and CVEs.
 *
 * Sorting rules (from the challenge spec):
 *   CVEs:         Score descending
 *   Dependencies: Severity desc -> Highest CVE score desc -> Name A-Z
 *   Repositories: Severity desc -> Highest CVE score desc -> Name A-Z
 */

/** Sort CVEs in place: score descending. Null scores sink to bottom. */
function sortCves(cves) {
  cves.sort(function (a, b) {
    var sa = a.score != null ? a.score : -1;
    var sb = b.score != null ? b.score : -1;
    return sb - sa;
  });
}

/**
 * Sort dependencies in place:
 *   1. Severity descending
 *   2. Highest CVE score descending
 *   3. Name A-Z
 */
function sortDependencies(deps) {
  deps.sort(function (a, b) {
    var sevDiff = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
    if (sevDiff !== 0) return sevDiff;

    var sa = a.maxScore != null ? a.maxScore : -1;
    var sb = b.maxScore != null ? b.maxScore : -1;
    if (sb !== sa) return sb - sa;

    return a.name.localeCompare(b.name);
  });
}

/**
 * Sort repos in place:
 *   1. Severity descending
 *   2. Highest CVE score descending
 *   3. Repo name A-Z
 */
function sortRepos(repos) {
  repos.sort(function (a, b) {
    var sevDiff = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
    if (sevDiff !== 0) return sevDiff;

    var sa = a.maxScore != null ? a.maxScore : -1;
    var sb = b.maxScore != null ? b.maxScore : -1;
    if (sb !== sa) return sb - sa;

    return a.repo.localeCompare(b.repo);
  });
}