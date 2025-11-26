# Shai-Hulud Detection Script

A Python-based security tool to scan GitHub repositories for npm packages compromised by the Shai-Hulud worm malware campaign.

## Overview

The Shai-Hulud campaign is a supply chain attack targeting the JavaScript/Node.js ecosystem through malicious npm packages. This tool helps developers and security teams audit their projects to identify potentially compromised dependencies by checking against the [Wiz Security IOC list](https://github.com/wiz-sec-public/wiz-research-iocs).

## Features

- Scan GitHub repositories (all branches and open PRs)
- Scan multiple local git repositories in a directory
- Support for multiple lock file formats:
  - `package-lock.json` (npm)
  - `yarn.lock` (Yarn v1)
  - `pnpm-lock.yaml` (pnpm v6+)
  - `package.json` (fallback for version ranges)
- JSON export for CI/CD integration
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

# Just list dependency files found (no malware check)
uv run python main.py --repo owner/repo --list-lock-files
```

### Custom Malicious Package List

```bash
# Use a custom CSV of malicious packages
uv run python main.py --repo owner/repo --malicious-list-url https://example.com/packages.csv
```

## How It Works

1. Fetches the latest list of malicious packages from Wiz Security's IOC repository
2. Connects to GitHub API to retrieve repository branches and open PRs
3. For each ref, locates dependency lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`)
4. Parses lock files to extract exact package versions
5. Compares installed packages against the malicious package list
6. Reports any matches with details about the affected ref and lock file

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
