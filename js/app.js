/**
 * app.js — Initialisation, data loading, and Phase 2 UI controls.
 */

// ---------------------------------------------------------------------------
// Config: static JSON file paths
// ---------------------------------------------------------------------------

var STATIC_REPOS = [
  { name: 'openmrs-core',           url: 'data/openmrs-core.json' },
  { name: 'openmrs-module-billing',  url: 'data/openmrs-module-billing.json' },
  { name: 'openmrs-module-idgen',    url: 'data/openmrs-module-idgen.json' }
];


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function showLoading(msg) {
  var el = document.getElementById('loading');
  el.textContent = msg || 'Loading vulnerability data...';
  el.classList.remove('hidden');
}

function hideLoading() {
  document.getElementById('loading').classList.add('hidden');
}

function showError(msg) {
  var el = document.getElementById('error');
  el.textContent = msg;
  el.classList.remove('hidden');
}

function hideError() {
  document.getElementById('error').classList.add('hidden');
}


// ---------------------------------------------------------------------------
// Static file loading
// ---------------------------------------------------------------------------

async function loadStaticData() {
  var repos = [];

  for (var i = 0; i < STATIC_REPOS.length; i++) {
    var entry = STATIC_REPOS[i];
    try {
      var res = await fetch(entry.url);
      if (!res.ok) throw new Error('HTTP ' + res.status);
      var json = await res.json();
      repos.push(parseReport(entry.name, json));
    } catch (err) {
      console.warn('Failed to load ' + entry.url + ':', err.message);
    }
  }

  return repos;
}


// ---------------------------------------------------------------------------
// Phase 2: Source selection UI
// ---------------------------------------------------------------------------

function buildSourceControls() {
  var div = document.createElement('div');
  div.className = 'source-controls';
  div.innerHTML =
    '<label for="data-source">Data source:</label>' +
    '<select id="data-source">' +
      '<option value="static">Static JSON files</option>' +
      '<option value="github">Latest from GitHub Actions</option>' +
    '</select>' +
    '<input type="password" id="gh-token" class="hidden" placeholder="GitHub Classic token (public_repo scope)" />' +
    '<button class="btn" id="load-btn">Load</button>';

  // Insert before the loading indicator
  var main = document.querySelector('main');
  var loading = document.getElementById('loading');
  main.insertBefore(div, loading);

  // Toggle token field visibility
  var select = document.getElementById('data-source');
  var tokenInput = document.getElementById('gh-token');
  select.addEventListener('change', function () {
    if (select.value === 'github') {
      tokenInput.classList.remove('hidden');
    } else {
      tokenInput.classList.add('hidden');
    }
  });

  // Load button handler
  var loadBtn = document.getElementById('load-btn');
  loadBtn.addEventListener('click', function () {
    loadDashboard();
  });
}


// ---------------------------------------------------------------------------
// Main loader
// ---------------------------------------------------------------------------

async function loadDashboard() {
  hideError();
  showLoading();

  var dashboard = document.getElementById('dashboard');
  dashboard.innerHTML = '';

  var source = document.getElementById('data-source').value;

  try {
    var repos;

    if (source === 'github') {
      var token = document.getElementById('gh-token').value.trim();
      if (!token) {
        throw new Error('Please enter a GitHub token.');
      }
      showLoading('Fetching latest data from GitHub Actions...');
      repos = await loadGitHubData(token);
    } else {
      repos = await loadStaticData();
    }

    if (!repos.length) {
      throw new Error('No vulnerability data found.');
    }

    hideLoading();
    renderDashboard(repos, 'dashboard');

  } catch (err) {
    hideLoading();
    showError('Error: ' + err.message);
    console.error(err);
  }
}


// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', function () {
  buildSourceControls();
  loadDashboard();
});