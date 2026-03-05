/**
 * github.js — Phase 2: Fetch the latest dependency-check report
 * directly from GitHub Actions artifacts.
 *
 * Flow:
 *  1. List artifacts for the repo (filtered by name)
 *  2. Download the latest artifact as a ZIP
 *  3. Unzip in-browser using JSZip
 *  4. Parse the JSON report inside
 *
 * Token: Use a Classic token (not fine-grained) with `public_repo` scope.
 * Fine-grained tokens may not work for repos you don't own.
 */

/** GitHub repos to pull artifacts from. */
var GITHUB_REPOS = [
  'openmrs/openmrs-core',
  'openmrs/openmrs-module-billing',
  'openmrs/openmrs-module-idgen'
];

/**
 * Fetch the latest dependency-check artifact for a GitHub repo.
 * @param {string} repoFullName  - e.g. "openmrs/openmrs-core"
 * @param {string} token         - GitHub Classic PAT with public_repo scope
 * @returns {Promise<object>}    - parsed JSON report
 */
async function fetchLatestArtifact(repoFullName, token) {
  var headers = {
    Accept: 'application/vnd.github+json',
    Authorization: 'Bearer ' + token
  };

  // 1. List artifacts filtered by name
  var listUrl =
    'https://api.github.com/repos/' + repoFullName +
    '/actions/artifacts?name=Dependency+Check+report&per_page=1';

  var listRes = await fetch(listUrl, { headers: headers });

  if (listRes.status === 401 || listRes.status === 403) {
    throw new Error(
      'Token invalid or lacks permissions. ' +
      'Use a Classic token (Settings > Developer settings > Tokens classic) with public_repo scope.'
    );
  }
  if (!listRes.ok) throw new Error('GitHub API error: ' + listRes.status);

  var listData = await listRes.json();

  if (!listData.artifacts || !listData.artifacts.length) {
    throw new Error('No "Dependency Check report" artifact found for ' + repoFullName);
  }

  var artifact = listData.artifacts[0];

  // 2. Download the artifact ZIP
  var zipRes;
  try {
    zipRes = await fetch(artifact.archive_download_url, { headers: headers });
  } catch (networkErr) {
    throw new Error(
      'Download blocked (likely CORS). Try using static JSON files instead.'
    );
  }

  if (!zipRes.ok) throw new Error('Artifact download failed: ' + zipRes.status);

  // 3. Unzip using JSZip
  if (typeof JSZip === 'undefined') {
    throw new Error('JSZip is not loaded.');
  }

  var zipBlob = await zipRes.blob();
  var zip = await JSZip.loadAsync(zipBlob);

  // 4. Find the JSON report inside the ZIP
  // Prefer dependency-check-report.json (richer data with scores, CWE)
  // over dependency-check-gitlab.json (limited fields)
  var jsonEntry = null;
  var fallbackEntry = null;
  zip.forEach(function (path, entry) {
    if (path.indexOf('dependency-check-report.json') !== -1) {
      jsonEntry = entry;
    } else if (!fallbackEntry && path.endsWith('.json')) {
      fallbackEntry = entry;
    }
  });

  if (!jsonEntry) jsonEntry = fallbackEntry;
  if (!jsonEntry) throw new Error('No JSON file found in artifact ZIP.');

  var text = await jsonEntry.async('text');
  return JSON.parse(text);
}

/**
 * Fetch latest reports for all configured repos.
 * @param {string} token - GitHub Classic PAT
 * @returns {Promise<Array>} - array of parsed repo objects
 */
async function loadGitHubData(token) {
  var repos = [];
  var errors = [];

  for (var i = 0; i < GITHUB_REPOS.length; i++) {
    var fullName = GITHUB_REPOS[i];
    var shortName = fullName.split('/')[1];

    try {
      var json = await fetchLatestArtifact(fullName, token);
      repos.push(parseReport(shortName, json));
    } catch (err) {
      console.warn('Could not fetch artifact for ' + fullName + ':', err.message);
      errors.push(shortName + ': ' + err.message);
    }
  }

  // If ALL repos failed, throw so the UI shows the error
  if (!repos.length && errors.length) {
    throw new Error('Could not fetch any artifacts. ' + errors[0]);
  }

  return repos;
}