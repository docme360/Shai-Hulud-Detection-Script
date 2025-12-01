# Shai-Hulud Detection Script

A Python-based security tool to scan GitHub repositories for npm packages compromised by the Shai-Hulud worm malware campaign, plus security hygiene checks to help protect against future attacks.

## Overview

The Shai-Hulud campaign is a supply chain attack targeting the JavaScript/Node.js ecosystem through malicious npm packages. This tool helps developers and security teams audit their projects to identify potentially compromised dependencies by checking against the [Wiz Security IOC list](https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv).

## Features

### Malware Detection
- Scan GitHub repositories (all branches and open PRs)
- Scan multiple local git repositories in a directory
- Support for multiple lock file formats:
  - `package-lock.json` (npm)
  - `yarn.lock` (Yarn v1)
  - `pnpm-lock.yaml` (pnpm v6+)
  - `package.json` (fallback for version ranges)

### Security Hygiene Checks (Always Enabled)
- **Non-pinned dependencies**: Detects version ranges (`^`, `~`, `>=`), wildcards (`*`, `latest`), and git URLs without commit hashes
- **Missing lock files**: Alerts when `package.json` exists without a corresponding lock file
- **Lockfile injection detection**: Identifies suspicious resolved URLs pointing to untrusted hosts or using HTTP
- **Dependency bot analysis**: Detects Dependabot/Renovate configs and warns about auto-merge risks

### Output
- JSON export for CI/CD integration (includes both malware findings and security warnings)
- General security recommendations printed at end of scan
- Zero external dependencies (uses only Python stdlib)

## Requirements

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip
- GitHub token (optional, but recommended for private repos and higher rate limits)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/custom-shai-hulud.git
cd custom-shai-hulud

# Install dependencies
uv sync
```

## Usage

### Scan a GitHub Repository

```bash
# Scan a public repository
uv run python main.py --repo owner/repo-name

# Scan with GitHub token (recommended)
uv run python main.py --repo owner/repo --github-token ghp_xxxx

# Scan only branches or only PRs
uv run python main.py --repo owner/repo --branches-only
uv run python main.py --repo owner/repo --prs-only
```

### Scan Local Repositories

```bash
# Scan all git repos in a directory
uv run python main.py --local-path ~/projects --github-token ghp_xxxx

# Limit directory search depth
uv run python main.py --local-path ~/projects --max-depth 2
```

### Output Options

```bash
# Export results to JSON
uv run python main.py --repo owner/repo --output results.json

# Verbose/debug mode
uv run python main.py --repo owner/repo --verbose
```


## How It Works

1. Fetches the latest list of malicious packages from Wiz Security's IOC repository
2. Connects to GitHub API to retrieve repository branches and open PRs
3. For each ref, locates dependency lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`)
4. Parses lock files to extract exact package versions
5. Compares installed packages against the malicious package list
6. Performs security hygiene checks:
   - Checks for unpinned dependencies in package.json
   - Verifies lock files exist for each package.json
   - Scans lockfiles for suspicious resolved URLs
   - Detects Dependabot/Renovate configurations
7. Reports findings and provides security recommendations

## Security Recommendations

The tool provides actionable security guidance based on [Snyk's npm security best practices](https://snyk.io/articles/npm-security-best-practices-shai-hulud-attack/):

1. **Use deterministic installs**: `npm ci`, `yarn --frozen-lockfile`, `pnpm --frozen-lockfile`
2. **Disable postinstall scripts**: `npm ci --ignore-scripts`
3. **Avoid blind dependency upgrades**: Never run `npm update` or `npx npm-check-updates -u`
4. **Validate lockfiles**: Use `lockfile-lint` to detect injection attacks
5. **Use version cooldown**: Avoid brand-new package versions with pnpm's `minimumReleaseAge`
6. **Use dev containers**: Sandbox development to limit blast radius

## GitHub API Rate Limits

- **Unauthenticated**: 60 requests/hour
- **With token**: 5,000 requests/hour

For scanning repositories with many branches/PRs, using a GitHub token is strongly recommended.

## GitHub Personal Access Token

To run the script against private repos, you need to create a Github Personal Access Token in order to access.

To create the token:
1. Go to your github page and click on your avatar.
2. Click on Settings
3. At the bottom of the left sidebar, click on `Developer settings`
4. At the bottom of the left sidebar, click on `Personal access tokens` -> `Tokens (classic)`
5. Click on `Generate new token(classic)`
6. Give token a name and in the `Select scopes` section, select the checkbox next to `repo` to get full control of private repositories.
7. Click on `Generate token`
8. Copy the token. **Note** - This will not be shown again so copy it and save it to a safe place.

Run the script with the copied token.

**Note** - When you are done checking your repos, it would be good to delete the token from Github.

## Contributing

Contributions are welcome! If you discover additional malicious packages or have improvements to the detection logic, please open an issue or submit a pull request.

## Disclaimer

This tool is provided for defensive security purposes only. Always verify findings and keep your detection lists updated as new threats are discovered.

## License

See repository for license information.
