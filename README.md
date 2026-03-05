# OpenMRS Dependency Vulnerability Dashboard

A static dashboard that visualizes dependency security vulnerabilities across OpenMRS repositories.
Built with plain HTML, CSS, and vanilla JavaScript. No frameworks, no build tools, no npm.

## 🚀Live Demo 
**View the dashboard here:** https://openmrs-contrib-dependancy-vulnerab.vercel.app/

## Getting Started

```bash
# Serve locally
python3 -m http.server 8080

# Open in browser
http://localhost:8080
```

Or simply open `index.html` directly.

## Features

- Collapsible repo sections sorted by severity
- Expandable dependency rows showing CVE details with CVSS scores, CWE, and fix versions
- CVE IDs link to NVD / GitHub Advisory pages
- Scrollable panels for repos with many dependencies or CVEs
- Severity pills (Critical, High, Medium, Low)
- Exploit detection from vulnerability references
- Graceful handling of missing data
- Phase 2: Live data fetching from GitHub Actions artifacts

## Data Format

The dashboard supports two JSON report formats and auto-detects which one is being loaded:

- **OWASP format** (`dependency-check-report.json`): Rich data with CVSS scores, CWE, affected version ranges, and fix versions. This is the preferred format.
- **GitLab format** (`dependency-check-gitlab.json`): Limited fields, used as a fallback.

The static JSON files in `data/` use the OWASP format, downloaded from the latest GitHub Actions runs.

## Sorting Logic

As defined in the challenge spec:

| Level        | Sort Order                                           |
|--------------|------------------------------------------------------|
| Repositories | Severity desc, Highest CVE score desc, Name A-Z     |
| Dependencies | Severity desc, Highest CVE score desc, Name A-Z     |
| CVEs         | Score desc                                           |

## Phase 2: Live Data from GitHub Actions

The dashboard can optionally fetch the latest dependency-check reports directly from GitHub Actions artifacts instead of using static files.

1. Select "Latest from GitHub Actions" from the dropdown
2. Enter a GitHub Classic token with `public_repo` scope
3. Click Load

The Phase 2 fetcher automatically prefers `dependency-check-report.json` (OWASP format) over the GitLab format when both are present in the artifact ZIP.

This is fully optional. The dashboard works out of the box with the static JSON files.

## Project Structure

```
index.html              Entry point
css/
  style.css             All styles
js/
  utils.js              Shared helpers (severity ranking, escaping, markdown stripping)
  dataParser.js         Auto-detecting parser for both JSON formats
  sorting.js            Sorting comparators for repos, deps, and CVEs
  renderer.js           DOM rendering and accordion toggle handlers
  github.js             Phase 2: GitHub Actions artifact fetching
  app.js                Config, data loading, and initialization
data/
  openmrs-core.json
  openmrs-module-billing.json
  openmrs-module-idgen.json
```

## License

[MPL-2.0](LICENSE)
