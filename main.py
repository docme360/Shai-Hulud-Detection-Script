#!/usr/bin/env python3
"""
NPM Malicious Package Scanner for GitHub Repositories

Scans all branches and open PRs in a GitHub repository for known malicious npm packages
by analyzing package-lock.json and yarn.lock files.
"""

import argparse
import base64
import csv
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# --- Data Classes ---

@dataclass
class ScanResult:
    """Represents a single malicious package finding."""
    ref_name: str
    ref_type: str  # 'branch' or 'pr'
    package_name: str
    installed_version: str
    affected_version: str
    lock_file: str
    is_exact_version: bool = True  # False if from package.json (version range)


@dataclass
class RefInfo:
    """Represents a git ref (branch or PR) to scan."""
    name: str
    ref_type: str  # 'branch' or 'pr'
    sha: str
    pr_number: Optional[int] = None


@dataclass
class SecurityWarning:
    """Represents a security hygiene warning."""
    warning_type: str  # 'unpinned_dependency', 'missing_lock_file', 'lockfile_injection', 'dependency_bot'
    severity: str  # 'high', 'medium', 'low', 'info'
    file_path: str
    message: str
    package_name: Optional[str] = None
    details: Optional[str] = None


@dataclass
class RepoAccessInfo:
    """Represents access information for a repository."""
    repo_name: str
    collaborators: list[dict]  # Direct user access
    teams: list[dict]  # Team access with members


# --- GitHub API ---

class GitHubAPI:
    """Simple GitHub API client using urllib."""
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self, token: Optional[str] = None, verbose: bool = False):
        self.token = token
        self.verbose = verbose
    
    def _request(self, endpoint: str) -> dict | list:
        """Make a GET request to the GitHub API."""
        url = f"{self.BASE_URL}{endpoint}"
        if self.verbose:
            print(f"    [DEBUG] GET {url}")
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "npm-malicious-scanner"
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as response:
                # Check rate limit headers
                remaining = response.headers.get('X-RateLimit-Remaining')
                if self.verbose and remaining:
                    print(f"    [DEBUG] Rate limit remaining: {remaining}")
                data = json.loads(response.read().decode('utf-8'))
                if self.verbose:
                    if isinstance(data, list):
                        print(f"    [DEBUG] Response: {len(data)} items")
                    else:
                        print(f"    [DEBUG] Response: dict with keys {list(data.keys())[:5]}...")
                return data
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace')
            if self.verbose:
                print(f"    [DEBUG] HTTP {e.code}: {e.reason}")
                print(f"    [DEBUG] Response body: {body[:500]}")
            
            if e.code == 404:
                # For file content requests, 404 just means file doesn't exist
                if "/contents/" in endpoint:
                    if self.verbose:
                        print(f"    [DEBUG] File not found (normal if file doesn't exist)")
                    return None
                # For other endpoints, could be repo not found or permissions
                print(f"Error: Got 404 for {endpoint}")
                print(f"  This usually means the resource doesn't exist or insufficient permissions.")
                return None
            elif e.code == 403:
                print(f"Error: Access denied (403)")
                if "rate limit" in body.lower():
                    print(f"  Rate limit exceeded. Use --github-token for higher limits.")
                else:
                    print(f"  Token may lack required permissions.")
                    print(f"  Required: 'repo' scope (classic) or 'Contents: read' (fine-grained)")
                sys.exit(1)
            else:
                print(f"Error: GitHub API returned {e.code}: {e.reason}")
                print(f"  Response: {body[:500]}")
                sys.exit(1)
    
    def check_token_scopes(self) -> Optional[list[str]]:
        """Check what scopes/permissions the token has."""
        url = f"{self.BASE_URL}/user"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "npm-malicious-scanner"
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as response:
                scopes = response.headers.get('X-OAuth-Scopes', '')
                return [s.strip() for s in scopes.split(',') if s.strip()]
        except urllib.error.HTTPError:
            return None
    
    def check_repo_access(self, owner: str, repo: str) -> dict:
        """Check if we have access to a repo and what permissions we have."""
        data = self._request(f"/repos/{owner}/{repo}")
        return data

    def get_default_branch(self, owner: str, repo: str) -> Optional[str]:
        """Get the default branch name for a repository."""
        data = self._request(f"/repos/{owner}/{repo}")
        if data:
            return data.get("default_branch")
        return None

    def get_branch(self, owner: str, repo: str, branch_name: str) -> Optional[RefInfo]:
        """Get a specific branch by name."""
        data = self._request(f"/repos/{owner}/{repo}/branches/{branch_name}")
        if data:
            return RefInfo(
                name=data["name"],
                ref_type="branch",
                sha=data["commit"]["sha"]
            )
        return None

    def get_repo_tree(self, owner: str, repo: str, sha: str) -> list[dict]:
        """Get the full file tree for a commit (recursive)."""
        data = self._request(f"/repos/{owner}/{repo}/git/trees/{sha}?recursive=1")
        if data and "tree" in data:
            return data["tree"]
        return []
    
    def find_dependency_files(self, owner: str, repo: str, sha: str) -> list[str]:
        """Find all lock files and package.json files in the repo (recursive)."""
        tree = self.get_repo_tree(owner, repo, sha)
        lock_files = []
        package_jsons = []
        
        for item in tree:
            if item.get("type") == "blob":
                path = item.get("path", "")
                # Prioritize lock files
                if (path.endswith("package-lock.json") or 
                    path.endswith("yarn.lock") or
                    path.endswith("pnpm-lock.yaml")):
                    lock_files.append(path)
                # Also track package.json for fallback
                elif path.endswith("package.json"):
                    package_jsons.append(path)
        
        # Return lock files first, then package.json files
        # This allows us to prefer lock files but fall back to package.json
        return lock_files + package_jsons
    
    def get_branches(self, owner: str, repo: str) -> list[RefInfo]:
        """Get all branches in a repository."""
        branches = []
        page = 1
        while True:
            if self.verbose:
                print(f"    [DEBUG] Fetching branches page {page}...")
            data = self._request(f"/repos/{owner}/{repo}/branches?per_page=100&page={page}")
            if not data:
                if self.verbose:
                    print(f"    [DEBUG] No data returned, stopping pagination")
                break
            if self.verbose:
                print(f"    [DEBUG] Page {page}: got {len(data)} branches")
            for branch in data:
                branches.append(RefInfo(
                    name=branch["name"],
                    ref_type="branch",
                    sha=branch["commit"]["sha"]
                ))
            if len(data) < 100:
                if self.verbose:
                    print(f"    [DEBUG] Less than 100 results, stopping pagination")
                break
            page += 1
        if self.verbose:
            print(f"    [DEBUG] Total branches collected: {len(branches)}")
        return branches
    
    def get_open_prs(self, owner: str, repo: str) -> list[RefInfo]:
        """Get all open PRs in a repository."""
        prs = []
        page = 1
        while True:
            data = self._request(f"/repos/{owner}/{repo}/pulls?state=open&per_page=100&page={page}")
            if not data:
                break
            for pr in data:
                prs.append(RefInfo(
                    name=f"PR #{pr['number']}: {pr['title'][:50]}",
                    ref_type="pr",
                    sha=pr["head"]["sha"],
                    pr_number=pr["number"]
                ))
            if len(data) < 100:
                break
            page += 1
        return prs
    
    def get_file_content(self, owner: str, repo: str, path: str, ref: str) -> Optional[str]:
        """Get the content of a file at a specific ref."""
        # URL-encode the path to handle spaces and special characters
        encoded_path = urllib.parse.quote(path, safe='/')
        data = self._request(f"/repos/{owner}/{repo}/contents/{encoded_path}?ref={ref}")
        if data is None or isinstance(data, list):
            return None
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode('utf-8')
        return None

    def get_collaborators(self, owner: str, repo: str) -> list[dict]:
        """Get all collaborators (users with direct access) for a repository."""
        collaborators = []
        page = 1
        while True:
            if self.verbose:
                print(f"    [DEBUG] Fetching collaborators page {page}...")
            data = self._request(f"/repos/{owner}/{repo}/collaborators?per_page=100&page={page}")
            if not data:
                break
            for user in data:
                collaborators.append({
                    "login": user.get("login"),
                    "type": "user",
                    "permissions": user.get("permissions", {}),
                    "role_name": user.get("role_name", "unknown")
                })
            if len(data) < 100:
                break
            page += 1
        return collaborators

    def get_repo_teams(self, owner: str, repo: str) -> list[dict]:
        """Get all teams with access to a repository."""
        teams = []
        page = 1
        while True:
            if self.verbose:
                print(f"    [DEBUG] Fetching repo teams page {page}...")
            data = self._request(f"/repos/{owner}/{repo}/teams?per_page=100&page={page}")
            if not data:
                break
            for team in data:
                teams.append({
                    "name": team.get("name"),
                    "slug": team.get("slug"),
                    "permission": team.get("permission"),
                    "privacy": team.get("privacy")
                })
            if len(data) < 100:
                break
            page += 1
        return teams

    def get_team_members(self, org: str, team_slug: str) -> list[dict]:
        """Get all members of a team."""
        members = []
        page = 1
        while True:
            if self.verbose:
                print(f"    [DEBUG] Fetching team {team_slug} members page {page}...")
            data = self._request(f"/orgs/{org}/teams/{team_slug}/members?per_page=100&page={page}")
            if not data:
                break
            for member in data:
                members.append({
                    "login": member.get("login"),
                    "type": member.get("type", "User")
                })
            if len(data) < 100:
                break
            page += 1
        return members


# --- Lock File Parsers ---

def parse_package_lock_json(content: str) -> dict[str, str]:
    """
    Parse package-lock.json and extract all packages with versions.
    Supports both lockfileVersion 2/3 format.
    
    Returns:
        dict: {package_name: version}
    """
    packages = {}
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return packages
    
    # lockfileVersion 2/3 uses "packages" key
    if "packages" in data:
        for path, info in data["packages"].items():
            if not path:  # Skip root package
                continue
            # Path format: "node_modules/pkg" or "node_modules/@scope/pkg"
            # or nested: "node_modules/pkg/node_modules/nested-pkg"
            parts = path.split("node_modules/")
            if parts:
                pkg_name = parts[-1]  # Get the last package name in the path
                if pkg_name and "version" in info:
                    packages[pkg_name] = info["version"]
    
    # lockfileVersion 1 uses "dependencies" key (legacy)
    elif "dependencies" in data:
        def extract_deps(deps: dict, prefix: str = ""):
            for name, info in deps.items():
                if isinstance(info, dict) and "version" in info:
                    packages[name] = info["version"]
                    # Handle nested dependencies
                    if "dependencies" in info:
                        extract_deps(info["dependencies"])
        extract_deps(data["dependencies"])
    
    return packages


def parse_yarn_lock(content: str) -> dict[str, str]:
    """
    Parse yarn.lock (v1 format) and extract all packages with versions.
    
    Yarn.lock format example:
    package-name@^1.0.0:
      version "1.2.3"
      resolved "..."
      
    Returns:
        dict: {package_name: version}
    """
    packages = {}
    
    # Regex to match package entries
    # Handles: "pkg@version:", "@scope/pkg@version:", and multiple versions "pkg@^1.0.0, pkg@^1.1.0:"
    package_pattern = re.compile(r'^"?(@?[^@\s"]+)@[^:]+:?\s*$', re.MULTILINE)
    version_pattern = re.compile(r'^\s+version\s+"([^"]+)"', re.MULTILINE)
    
    lines = content.split('\n')
    current_package = None
    
    for line in lines:
        # Skip comments
        if line.startswith('#'):
            continue
        
        # Check for package declaration
        # Handle formats like: "package@^1.0.0": or package@^1.0.0:
        stripped = line.rstrip()
        if stripped and not stripped.startswith(' ') and '@' in stripped:
            # Extract package name from "pkg@version:" or "@scope/pkg@version:"
            match = re.match(r'^"?(@?[^@\s"]+)@', stripped)
            if match:
                current_package = match.group(1)
        
        # Check for version line
        elif current_package and 'version' in line:
            version_match = re.match(r'^\s+version\s+"?([^"\s]+)"?', line)
            if version_match:
                packages[current_package] = version_match.group(1)
                current_package = None
    
    return packages


def parse_pnpm_lock(content: str) -> dict[str, str]:
    """
    Parse pnpm-lock.yaml and extract all packages with versions.
    
    pnpm-lock.yaml format (v6+):
    packages:
      /@scope/package@1.2.3:
        resolution: {...}
      /package@1.2.3:
        resolution: {...}
        
    Returns:
        dict: {package_name: version}
    """
    packages = {}
    
    # Simple line-by-line parsing (avoids yaml dependency)
    in_packages_section = False
    
    for line in content.split('\n'):
        stripped = line.strip()
        
        # Detect packages section
        if stripped == 'packages:':
            in_packages_section = True
            continue
        
        # Exit packages section on new top-level key
        if in_packages_section and line and not line.startswith(' ') and line.endswith(':'):
            in_packages_section = False
            continue
        
        if in_packages_section:
            # Match patterns like:
            # /@scope/pkg@1.2.3:
            # /pkg@1.2.3:
            # '@scope/pkg@1.2.3':
            # 'pkg@1.2.3':
            match = re.match(r"^\s+['\"]?/?(@?[^@'\"]+)@([^:'\"]+)['\"]?:", line)
            if match:
                pkg_name = match.group(1)
                version = match.group(2)
                # Clean up package name (remove leading /)
                pkg_name = pkg_name.lstrip('/')
                packages[pkg_name] = version
    
    return packages


def parse_package_json(content: str) -> dict[str, str]:
    """
    Parse package.json and extract all dependencies with version ranges.
    
    Note: package.json contains version RANGES (e.g., "^1.2.3"), not exact versions.
    This is used as a fallback when lock files aren't available.
    
    Returns:
        dict: {package_name: version_range}
    """
    packages = {}
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return packages
    
    # Check all dependency types
    dep_keys = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']
    
    for key in dep_keys:
        deps = data.get(key, {})
        if isinstance(deps, dict):
            for name, version in deps.items():
                if isinstance(version, str):
                    packages[name] = version
    
    return packages


def parse_affected_versions(version_string: str) -> set[str]:
    """
    Parse affected version strings from the IOC CSV.
    
    Formats supported:
    - "= 1.2.3" -> {"1.2.3"}
    - "= 1.2.3 || = 1.2.4" -> {"1.2.3", "1.2.4"}
    - "1.2.3" -> {"1.2.3"}
    
    Returns:
        set: Set of affected version strings
    """
    versions = set()
    
    # Split by "||" for multiple versions
    parts = version_string.split("||")
    
    for part in parts:
        part = part.strip()
        # Remove leading "=" or "= " if present
        if part.startswith("="):
            part = part[1:].strip()
        if part:
            versions.add(part)
    
    return versions


def normalize_version(version: str) -> str:
    """
    Normalize a version string by removing range specifiers.
    
    Examples:
    - "^1.2.3" -> "1.2.3"
    - "~1.2.3" -> "1.2.3"
    - ">=1.2.3" -> "1.2.3"
    - "1.2.3" -> "1.2.3"
    
    Returns:
        str: Normalized version string
    """
    # Remove common range specifiers
    version = version.strip()
    for prefix in ['^', '~', '>=', '<=', '>', '<', '=']:
        if version.startswith(prefix):
            version = version[len(prefix):]
    return version.strip()


def is_version_affected(installed_version: str, affected_version_string: str) -> bool:
    """
    Check if an installed version matches any of the affected versions.
    
    Args:
        installed_version: The version that's installed (e.g., "4.18.0" or "^4.18.0")
        affected_version_string: The affected versions string (e.g., "= 5.13.3 || = 4.18.1")
    
    Returns:
        bool: True if the installed version is in the affected versions
    """
    affected_versions = parse_affected_versions(affected_version_string)
    
    # Normalize the installed version (remove ^, ~, etc.)
    normalized_installed = normalize_version(installed_version)
    
    return normalized_installed in affected_versions


# --- Security Hygiene Checks ---

def check_unpinned_dependencies(content: str, file_path: str) -> list[SecurityWarning]:
    """
    Check package.json for non-pinned dependencies.

    Detects:
    - Version ranges using ^, ~, >=, >, <, <=
    - Wildcard versions: *, x, latest
    - Git URLs without commit hashes
    - npm tags (e.g., next, beta, canary)

    Returns:
        list of SecurityWarning objects
    """
    warnings = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return warnings

    dep_keys = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']

    # Common npm tags that aren't pinned versions
    npm_tags = {'latest', 'next', 'beta', 'alpha', 'canary', 'rc', 'experimental'}

    for key in dep_keys:
        deps = data.get(key, {})
        if not isinstance(deps, dict):
            continue

        for name, version in deps.items():
            if not isinstance(version, str):
                continue

            version = version.strip()
            reason = None

            # Check for range specifiers
            if version.startswith('^'):
                reason = "uses ^ range (allows minor updates)"
            elif version.startswith('~'):
                reason = "uses ~ range (allows patch updates)"
            elif version.startswith('>=') or version.startswith('>'):
                reason = "uses >= or > range"
            elif version.startswith('<=') or version.startswith('<'):
                reason = "uses <= or < range"
            # Check for wildcards
            elif version in ('*', 'x', 'X'):
                reason = "uses wildcard (any version)"
            elif '.x' in version or '.X' in version or '.*' in version:
                reason = "uses partial wildcard"
            # Check for npm tags
            elif version.lower() in npm_tags:
                reason = f"uses npm tag '{version}'"
            # Check for git URLs without pinned commit
            elif version.startswith('git://') or version.startswith('git+'):
                if '#' not in version:
                    reason = "git URL without pinned commit hash"
            elif version.startswith('github:') or '/' in version and not version[0].isdigit():
                if '#' not in version:
                    reason = "GitHub shorthand without pinned commit"
            # Check for URL-based dependencies
            elif version.startswith('http://') or version.startswith('https://'):
                if '#' not in version and not version.endswith('.tgz'):
                    reason = "URL dependency without pinned version"
            # Check for version ranges with ||
            elif '||' in version:
                reason = "uses version range with || (multiple ranges)"
            # Check for space-separated ranges (e.g., ">=1.0.0 <2.0.0")
            elif ' ' in version and any(c in version for c in ['^', '~', '>', '<', '=']):
                reason = "uses compound version range"

            if reason:
                warnings.append(SecurityWarning(
                    warning_type='unpinned_dependency',
                    severity='high',
                    file_path=file_path,
                    message=f"{name}: {version} ({reason})",
                    package_name=name,
                    details=f"Pin to exact version to prevent unexpected updates"
                ))

    return warnings


def check_missing_lock_files(dep_files: list[str]) -> list[SecurityWarning]:
    """
    Check for package.json files without corresponding lock files.

    Args:
        dep_files: List of dependency file paths found in the repo

    Returns:
        list of SecurityWarning objects for missing lock files
    """
    warnings = []

    # Group files by directory
    dirs_with_package_json = set()
    dirs_with_lock_file = set()

    for file_path in dep_files:
        # Get directory (or empty string for root)
        if '/' in file_path:
            dir_path = file_path.rsplit('/', 1)[0]
        else:
            dir_path = ''

        if file_path.endswith('package.json'):
            dirs_with_package_json.add((dir_path, file_path))
        elif file_path.endswith(('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml')):
            dirs_with_lock_file.add(dir_path)

    # Find package.json files without lock files in the same directory
    for dir_path, package_json_path in dirs_with_package_json:
        if dir_path not in dirs_with_lock_file:
            warnings.append(SecurityWarning(
                warning_type='missing_lock_file',
                severity='high',
                file_path=package_json_path,
                message=f"{package_json_path} has no lock file",
                details="Generate and commit a lock file:\n"
                        "  npm:  npm install -> creates package-lock.json\n"
                        "  yarn: yarn install -> creates yarn.lock\n"
                        "  pnpm: pnpm install -> creates pnpm-lock.yaml"
            ))

    return warnings


def check_lockfile_injection(content: str, file_path: str, file_type: str) -> list[SecurityWarning]:
    """
    Check lockfile for suspicious resolved URLs that may indicate lockfile injection.

    Detects:
    - Resolved URLs pointing to non-standard hosts (not npm, yarn, github)
    - HTTP URLs (should be HTTPS)
    - Tarball URLs to arbitrary hosts

    Args:
        content: The lockfile content
        file_path: Path to the lockfile
        file_type: Type of lockfile ('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml')

    Returns:
        list of SecurityWarning objects
    """
    warnings = []

    # Trusted hosts for package resolution
    trusted_hosts = [
        'registry.npmjs.org',
        'registry.yarnpkg.com',
        'npm.pkg.github.com',
        'registry.npmmirror.com',
        'github.com',
        'raw.githubusercontent.com',
    ]

    def is_trusted_url(url: str) -> bool:
        """Check if URL is from a trusted host."""
        url_lower = url.lower()
        # Check for HTTP (not HTTPS) - always suspicious
        if url_lower.startswith('http://'):
            return False
        for host in trusted_hosts:
            if host in url_lower:
                return True
        return False

    if file_type == 'package-lock.json':
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return warnings

        # Check packages in lockfileVersion 2/3 format
        packages = data.get('packages', {})
        for pkg_path, pkg_info in packages.items():
            if not pkg_path:  # Skip root
                continue
            resolved = pkg_info.get('resolved', '')
            if resolved and not is_trusted_url(resolved):
                pkg_name = pkg_path.split('node_modules/')[-1] if 'node_modules/' in pkg_path else pkg_path
                reason = "HTTP URL (not HTTPS)" if resolved.startswith('http://') else "untrusted host"
                warnings.append(SecurityWarning(
                    warning_type='lockfile_injection',
                    severity='high',
                    file_path=file_path,
                    message=f"{pkg_name}: resolves to {reason}",
                    package_name=pkg_name,
                    details=f"Resolved URL: {resolved[:100]}..."
                ))

        # Also check legacy dependencies format
        def check_deps(deps: dict, prefix: str = ""):
            for name, info in deps.items():
                if isinstance(info, dict):
                    resolved = info.get('resolved', '')
                    if resolved and not is_trusted_url(resolved):
                        reason = "HTTP URL (not HTTPS)" if resolved.startswith('http://') else "untrusted host"
                        warnings.append(SecurityWarning(
                            warning_type='lockfile_injection',
                            severity='high',
                            file_path=file_path,
                            message=f"{name}: resolves to {reason}",
                            package_name=name,
                            details=f"Resolved URL: {resolved[:100]}..."
                        ))
                    if 'dependencies' in info:
                        check_deps(info['dependencies'], f"{prefix}{name}/")

        if 'dependencies' in data:
            check_deps(data['dependencies'])

    elif file_type == 'yarn.lock':
        # Simple pattern matching for yarn.lock resolved URLs
        resolved_pattern = re.compile(r'^\s+resolved\s+"([^"]+)"', re.MULTILINE)
        for match in resolved_pattern.finditer(content):
            url = match.group(1)
            if not is_trusted_url(url):
                reason = "HTTP URL (not HTTPS)" if url.startswith('http://') else "untrusted host"
                warnings.append(SecurityWarning(
                    warning_type='lockfile_injection',
                    severity='high',
                    file_path=file_path,
                    message=f"Suspicious resolved URL ({reason})",
                    details=f"URL: {url[:100]}..."
                ))

    elif file_type == 'pnpm-lock.yaml':
        # Check for tarball URLs in pnpm lockfile
        # pnpm uses a different format, look for resolution URLs
        tarball_pattern = re.compile(r'tarball:\s*[\'"]?([^\s\'"]+)', re.MULTILINE)
        for match in tarball_pattern.finditer(content):
            url = match.group(1)
            if not is_trusted_url(url):
                reason = "HTTP URL (not HTTPS)" if url.startswith('http://') else "untrusted host"
                warnings.append(SecurityWarning(
                    warning_type='lockfile_injection',
                    severity='high',
                    file_path=file_path,
                    message=f"Suspicious tarball URL ({reason})",
                    details=f"URL: {url[:100]}..."
                ))

    return warnings


def find_dependency_bot_configs(tree: list[dict]) -> list[str]:
    """
    Find Dependabot and Renovate configuration files in the repo tree.

    Args:
        tree: List of file entries from GitHub API

    Returns:
        List of config file paths found
    """
    config_files = []
    bot_config_names = [
        '.github/dependabot.yml',
        '.github/dependabot.yaml',
        'renovate.json',
        'renovate.json5',
        '.renovaterc',
        '.renovaterc.json',
    ]

    for item in tree:
        if item.get('type') == 'blob':
            path = item.get('path', '')
            if path in bot_config_names:
                config_files.append(path)

    return config_files


def analyze_dependency_bot_config(content: str, config_path: str) -> list[SecurityWarning]:
    """
    Analyze dependency bot config for potentially risky settings.

    Args:
        content: The config file content
        config_path: Path to the config file

    Returns:
        list of SecurityWarning objects
    """
    warnings = []

    # Always warn about presence of dependency bot config
    if 'dependabot' in config_path.lower():
        bot_type = 'Dependabot'
    else:
        bot_type = 'Renovate'

    warnings.append(SecurityWarning(
        warning_type='dependency_bot',
        severity='info',
        file_path=config_path,
        message=f"{bot_type} configuration detected",
        details="Ensure only security updates are auto-merged, not all dependency updates"
    ))

    # Try to detect risky auto-merge settings
    try:
        if config_path.endswith(('.json', '.json5')):
            # Remove comments for json5
            clean_content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
            clean_content = re.sub(r'/\*.*?\*/', '', clean_content, flags=re.DOTALL)
            data = json.loads(clean_content)

            # Check Renovate automerge settings
            if data.get('automerge') is True:
                warnings.append(SecurityWarning(
                    warning_type='dependency_bot',
                    severity='medium',
                    file_path=config_path,
                    message="Renovate automerge is enabled globally",
                    details="Consider only enabling automerge for security updates or lockfile maintenance"
                ))
    except (json.JSONDecodeError, KeyError):
        pass  # Can't parse, just use the basic warning

    return warnings


# --- Malicious Package List ---

def fetch_affected_packages(
    url: str = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"
) -> dict[str, str]:
    """
    Fetches the CSV containing affected packages and parses it into a dict.
    
    Returns:
        dict: {package: version_info}
    """
    affected_packages = {}
    try:
        with urllib.request.urlopen(url) as response:
            lines = (line.decode('utf-8') for line in response)
            reader = csv.DictReader(lines)
            for row in reader:
                pkg = row.get("Package")
                ver = row.get("Version")
                if pkg and ver:
                    affected_packages[pkg] = ver
    except urllib.error.URLError as e:
        print(f"Warning: Could not fetch malicious package list: {e}")
    return affected_packages


# --- Scanner ---

class RepoScanner:
    """Scans a GitHub repository for malicious packages."""
    
    def __init__(self, owner: str, repo: str, github_token: Optional[str] = None, 
                 verbose: bool = False):
        self.owner = owner
        self.repo = repo
        self.api = GitHubAPI(github_token, verbose=verbose)
        self.affected_packages = {}
    
    def load_affected_packages(self, url: Optional[str] = None):
        """Load the list of known malicious packages."""
        if url:
            self.affected_packages = fetch_affected_packages(url)
        else:
            self.affected_packages = fetch_affected_packages()
        print(f"Loaded {len(self.affected_packages)} known malicious packages")
    
    def check_access(self) -> bool:
        """Verify we have proper access to the repository."""
        print(f"Checking access to {self.owner}/{self.repo}...")
        
        # Check token scopes (only works for classic tokens)
        scopes = self.api.check_token_scopes()
        if scopes is not None:
            print(f"  Token scopes: {', '.join(scopes) if scopes else '(none - fine-grained token or no scopes)'}")
            if scopes and 'repo' not in scopes:
                print(f"  ⚠️  Warning: 'repo' scope not found. May not be able to access private repos.")
        
        # Check repo access
        repo_info = self.api.check_repo_access(self.owner, self.repo)
        if repo_info is None:
            print(f"  ❌ Cannot access repository. Check that:")
            print(f"     - The repository exists")
            print(f"     - Your token has access to this repo")
            print(f"     - For private repos: token needs 'repo' scope (classic) or 'Contents: read' (fine-grained)")
            return False
        
        private = repo_info.get('private', False)
        permissions = repo_info.get('permissions', {})
        print(f"  Repository: {'private' if private else 'public'}")
        print(f"  Permissions: {permissions}")
        
        if not permissions.get('pull', False):
            print(f"  ⚠️  Warning: No 'pull' permission. May not be able to read contents.")
        
        return True
    
    def scan_ref(self, ref: RefInfo, show_progress: bool = True) -> tuple[list[ScanResult], list[SecurityWarning]]:
        """Scan a single ref (branch or PR) for malicious packages and security issues."""
        results = []
        warnings = []

        # Find all dependency files in this ref
        dep_files = self.api.find_dependency_files(self.owner, self.repo, ref.sha)

        if not dep_files:
            if show_progress:
                print("(no dependency files)")
            return results, warnings

        # Check for missing lock files
        warnings.extend(check_missing_lock_files(dep_files))

        # Separate lock files from package.json files
        lock_files = [f for f in dep_files if not f.endswith('package.json')]
        package_jsons = [f for f in dep_files if f.endswith('package.json')]

        # Always scan both lock files AND package.json files
        # This catches:
        # - Actually installed malicious packages (from lock files)
        # - Declared but not-yet-installed malicious packages (from package.json)
        files_to_scan = lock_files + package_jsons

        if show_progress:
            lock_count = len(lock_files)
            pj_count = len(package_jsons)
            parts = []
            if lock_count:
                parts.append(f"{lock_count} lock file(s)")
            if pj_count:
                parts.append(f"{pj_count} package.json")
            print(f"({', '.join(parts)})...", end=" ")

        for file_path in files_to_scan:
            # Determine parser and if it's exact version
            is_exact = True
            file_type = None
            if file_path.endswith("package-lock.json"):
                parser = parse_package_lock_json
                file_type = 'package-lock.json'
            elif file_path.endswith("yarn.lock"):
                parser = parse_yarn_lock
                file_type = 'yarn.lock'
            elif file_path.endswith("pnpm-lock.yaml"):
                parser = parse_pnpm_lock
                file_type = 'pnpm-lock.yaml'
            elif file_path.endswith("package.json"):
                parser = parse_package_json
                is_exact = False
            else:
                continue

            content = self.api.get_file_content(self.owner, self.repo, file_path, ref.sha)
            if content:
                packages = parser(content)

                # Check for malicious packages
                for pkg_name, installed_version in packages.items():
                    if pkg_name in self.affected_packages:
                        affected_version_string = self.affected_packages[pkg_name]

                        # Actually check if the installed version matches an affected version
                        if is_version_affected(installed_version, affected_version_string):
                            results.append(ScanResult(
                                ref_name=ref.name,
                                ref_type=ref.ref_type,
                                package_name=pkg_name,
                                installed_version=installed_version,
                                affected_version=affected_version_string,
                                lock_file=file_path,
                                is_exact_version=is_exact
                            ))

                # Security hygiene checks
                if file_path.endswith("package.json"):
                    # Check for unpinned dependencies
                    warnings.extend(check_unpinned_dependencies(content, file_path))
                elif file_type:
                    # Check lockfiles for injection attacks
                    warnings.extend(check_lockfile_injection(content, file_path, file_type))

        return results, warnings
    
    def scan_all(self, include_branches: bool = True, include_prs: bool = True,
                 default_branch_only: bool = False) -> tuple[list[ScanResult], list[SecurityWarning]]:
        """Scan all branches and/or PRs in the repository."""
        all_results = []
        all_warnings = []
        refs_to_scan = []

        if default_branch_only:
            # Only scan the default branch
            default_branch_name = self.api.get_default_branch(self.owner, self.repo)
            if default_branch_name:
                print(f"Fetching default branch '{default_branch_name}' for {self.owner}/{self.repo}...")
                default_ref = self.api.get_branch(self.owner, self.repo, default_branch_name)
                if default_ref:
                    refs_to_scan.append(default_ref)
                else:
                    print(f"  ⚠️  Could not fetch default branch")
            else:
                print(f"  ⚠️  Could not determine default branch")
        else:
            if include_branches:
                print(f"Fetching branches for {self.owner}/{self.repo}...")
                branches = self.api.get_branches(self.owner, self.repo)
                print(f"  Found {len(branches)} branches")
                refs_to_scan.extend(branches)

            if include_prs:
                print(f"Fetching open PRs for {self.owner}/{self.repo}...")
                prs = self.api.get_open_prs(self.owner, self.repo)
                print(f"  Found {len(prs)} open PRs")
                refs_to_scan.extend(prs)

        if not refs_to_scan:
            print("No refs to scan.")
            return all_results, all_warnings

        # Show what dependency files exist on the first ref (usually main/default branch)
        print(f"\nDiscovering dependency files on {refs_to_scan[0].name}...")
        sample_files = self.api.find_dependency_files(self.owner, self.repo, refs_to_scan[0].sha)
        if sample_files:
            lock_files = [f for f in sample_files if not f.endswith('package.json')]
            package_jsons = [f for f in sample_files if f.endswith('package.json')]

            if lock_files:
                print(f"  Lock files ({len(lock_files)}):")
                for lf in sorted(lock_files):
                    print(f"    📄 {lf}")
            if package_jsons:
                print(f"  package.json files ({len(package_jsons)}):")
                for pj in sorted(package_jsons):
                    print(f"    📦 {pj}")
        else:
            print("  ⚠️  No dependency files found on default branch")

        # Check for dependency bot configs on the default branch
        tree = self.api.get_repo_tree(self.owner, self.repo, refs_to_scan[0].sha)
        bot_configs = find_dependency_bot_configs(tree)
        for config_path in bot_configs:
            content = self.api.get_file_content(self.owner, self.repo, config_path, refs_to_scan[0].sha)
            if content:
                all_warnings.extend(analyze_dependency_bot_config(content, config_path))

        print(f"\nScanning {len(refs_to_scan)} refs...")

        # We only need to scan the default branch for security warnings (they're repo-wide)
        # But we scan all refs for malicious packages
        seen_warnings = set()  # Deduplicate warnings by (type, file_path, message)

        for i, ref in enumerate(refs_to_scan, 1):
            print(f"  [{i}/{len(refs_to_scan)}] {ref.ref_type}: {ref.name[:50]}... ", end="")
            results, warnings = self.scan_ref(ref, show_progress=True)
            if results:
                print(f"⚠️  {len(results)} match(es)!")
            else:
                print("✓ clean")
            all_results.extend(results)

            # Only add unique warnings (avoid duplicates from multiple refs)
            for w in warnings:
                key = (w.warning_type, w.file_path, w.message)
                if key not in seen_warnings:
                    seen_warnings.add(key)
                    all_warnings.append(w)

        return all_results, all_warnings

    def get_access_info(self) -> RepoAccessInfo:
        """Fetch repository access information (collaborators and teams with members)."""
        print(f"\nFetching repository access information...")

        # Get direct collaborators
        collaborators = self.api.get_collaborators(self.owner, self.repo)
        print(f"  Found {len(collaborators)} collaborator(s)")

        # Get teams with access
        teams_raw = self.api.get_repo_teams(self.owner, self.repo)
        print(f"  Found {len(teams_raw)} team(s)")

        # For each team, fetch its members
        teams_with_members = []
        for team in teams_raw:
            members = self.api.get_team_members(self.owner, team["slug"])
            teams_with_members.append({
                "name": team["name"],
                "slug": team["slug"],
                "permission": team["permission"],
                "privacy": team.get("privacy"),
                "members": members
            })
            if members:
                print(f"    • {team['name']}: {len(members)} member(s)")

        return RepoAccessInfo(
            repo_name=f"{self.owner}/{self.repo}",
            collaborators=collaborators,
            teams=teams_with_members
        )


# --- Output Formatting ---

def print_results(results: list[ScanResult]):
    """Print scan results in a readable format."""
    if not results:
        print("\n" + "=" * 60)
        print("✅ No malicious packages detected!")
        print("=" * 60)
        return
    
    print("\n" + "=" * 60)
    print(f"⚠️  ALERT: Found {len(results)} malicious package match(es)!")
    print("=" * 60)
    
    # Group by ref
    by_ref = {}
    for r in results:
        key = (r.ref_name, r.ref_type)
        if key not in by_ref:
            by_ref[key] = []
        by_ref[key].append(r)
    
    for (ref_name, ref_type), ref_results in by_ref.items():
        print(f"\n📁 {ref_type.upper()}: {ref_name}")
        print("-" * 50)
        for r in ref_results:
            print(f"  ❌ {r.package_name}")
            if r.is_exact_version:
                print(f"     Installed version: {r.installed_version}")
            else:
                print(f"     Declared range: {r.installed_version}  ⚠️  (from package.json - verify actual installed version)")
            print(f"     Affected version:  {r.affected_version}")
            print(f"     Found in: {r.lock_file}")


def export_json(results: list[ScanResult], warnings: list[SecurityWarning], filepath: str,
                access_info: Optional[list[RepoAccessInfo]] = None):
    """Export results, warnings, and repository access information to JSON file in the output folder."""
    data = {
        "malicious_packages": [
            {
                "ref_name": r.ref_name,
                "ref_type": r.ref_type,
                "package_name": r.package_name,
                "installed_version": r.installed_version,
                "affected_version": r.affected_version,
                "lock_file": r.lock_file,
                "is_exact_version": r.is_exact_version
            }
            for r in results
        ],
        "security_warnings": [
            {
                "warning_type": w.warning_type,
                "severity": w.severity,
                "file_path": w.file_path,
                "message": w.message,
                "package_name": w.package_name,
                "details": w.details
            }
            for w in warnings
        ]
    }

    # Add repository access information if provided
    if access_info:
        data["repository_access"] = [
            {
                "repo_name": info.repo_name,
                "collaborators": info.collaborators,
                "teams": info.teams
            }
            for info in access_info
        ]

    # Ensure output directory exists
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # Place the file in the output directory
    output_path = output_dir / Path(filepath).name

    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"\nResults exported to: {output_path}")


def print_security_warnings(warnings: list[SecurityWarning], repo_name: str = ""):
    """Print security warnings for a repository."""
    if not warnings:
        return

    # Group warnings by type
    unpinned = [w for w in warnings if w.warning_type == 'unpinned_dependency']
    missing_lock = [w for w in warnings if w.warning_type == 'missing_lock_file']
    lockfile_injection = [w for w in warnings if w.warning_type == 'lockfile_injection']
    dependency_bot = [w for w in warnings if w.warning_type == 'dependency_bot']

    header = f"SECURITY WARNINGS for {repo_name}" if repo_name else "SECURITY WARNINGS"
    print(f"\n⚠️  {header}:")
    print("-" * 50)

    if unpinned:
        print(f"\n⚠️  NON-PINNED DEPENDENCIES ({len(unpinned)} found)")
        print("   These use version ranges that could resolve to malicious versions:\n")
        for w in unpinned[:10]:  # Limit to first 10 to avoid overwhelming output
            print(f"   • {w.message}")
            print(f"     File: {w.file_path}")
        if len(unpinned) > 10:
            print(f"\n   ... and {len(unpinned) - 10} more unpinned dependencies")
        print(f"\n   Fix: Pin dependencies to exact versions (remove ^, ~, etc.)")

    if missing_lock:
        print(f"\n⚠️  MISSING LOCK FILES ({len(missing_lock)} found)")
        for w in missing_lock:
            print(f"   • {w.file_path}")
            print(f"     {w.details}")

    if lockfile_injection:
        print(f"\n⚠️  SUSPICIOUS LOCKFILE ENTRIES ({len(lockfile_injection)} found)")
        for w in lockfile_injection:
            print(f"   • {w.message}")
            print(f"     File: {w.file_path}")
            if w.details:
                print(f"     {w.details}")

    if dependency_bot:
        print(f"\nℹ️  DEPENDENCY BOT CONFIGURATION")
        for w in dependency_bot:
            if w.severity == 'info':
                print(f"   • {w.message}")
                print(f"     {w.details}")
            else:
                print(f"   ⚠️  {w.message}")
                print(f"     {w.details}")


def print_security_recommendations(quiet: bool = False):
    """Print general security recommendations once at end of all scans."""
    if quiet:
        return

    print("\n" + "=" * 60)
    print("💡 GENERAL SECURITY RECOMMENDATIONS")
    print("=" * 60)

    print("""
1. USE DETERMINISTIC INSTALLS
   Always use commands that install exactly what's in your lock file:
   • npm:  npm ci
   • yarn: yarn install --frozen-lockfile
   • pnpm: pnpm install --frozen-lockfile

2. DISABLE POSTINSTALL SCRIPTS
   Combine frozen lockfile with --ignore-scripts:
   • npm:  npm ci --ignore-scripts
   • yarn: yarn install --frozen-lockfile --ignore-scripts
   • pnpm: pnpm install --frozen-lockfile --ignore-scripts

   Note: pnpm v10+ and bun disable scripts by default.

3. AVOID BLIND DEPENDENCY UPGRADES
   Never run `npm update` or `npx npm-check-updates -u`.
   Use interactive mode or security-aware bots with PR review.

4. VALIDATE LOCKFILES
   Use lockfile-lint to detect lockfile injection attacks:
   npx lockfile-lint --path package-lock.json --allowed-hosts npm --validate-https

5. USE VERSION COOLDOWN
   Avoid brand-new package versions. Use pnpm's minimumReleaseAge or npq.

6. USE DEV CONTAINERS
   Sandbox your development environment to limit blast radius.

For more details: https://snyk.io/articles/npm-security-best-practices-shai-hulud-attack/
""")
    print("=" * 60)


# --- Main ---

def parse_repo_arg(repo_arg: str) -> tuple[str, str]:
    """Parse repository argument into owner and repo name."""
    # Handle full URLs
    if repo_arg.startswith("https://github.com/"):
        repo_arg = repo_arg.replace("https://github.com/", "")
    elif repo_arg.startswith("git@github.com:"):
        repo_arg = repo_arg.replace("git@github.com:", "")
    
    # Remove trailing .git if present
    repo_arg = repo_arg.rstrip("/").removesuffix(".git")
    
    # Split into owner/repo
    parts = repo_arg.split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]
    else:
        raise ValueError(f"Invalid repository format: {repo_arg}. Expected 'owner/repo' or GitHub URL.")


# --- Local Folder Scanning ---

def find_git_repos(root_path: str, max_depth: int = 5) -> list[Path]:
    """
    Recursively find all git repositories under a given path.
    
    Args:
        root_path: The root directory to search
        max_depth: Maximum depth to search (default 5)
    
    Returns:
        List of paths to git repositories
    """
    git_repos = []
    root = Path(root_path).resolve()
    
    if not root.exists():
        print(f"Error: Path does not exist: {root}")
        return git_repos
    
    if not root.is_dir():
        print(f"Error: Path is not a directory: {root}")
        return git_repos
    
    def search_dir(path: Path, depth: int):
        if depth > max_depth:
            return
        
        try:
            # Check if this directory is a git repo
            git_dir = path / ".git"
            if git_dir.exists() and git_dir.is_dir():
                git_repos.append(path)
                return  # Don't search inside git repos for nested repos
            
            # Search subdirectories
            for item in path.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    search_dir(item, depth + 1)
        except PermissionError:
            pass  # Skip directories we can't access
    
    search_dir(root, 0)
    return git_repos


def get_github_remote_url(repo_path: Path) -> Optional[str]:
    """
    Get the GitHub remote URL from a local git repository.
    
    Args:
        repo_path: Path to the git repository
    
    Returns:
        GitHub remote URL or None if not a GitHub repo
    """
    try:
        # Try to get the origin remote URL
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            return None
        
        url = result.stdout.strip()
        
        # Check if it's a GitHub URL
        if "github.com" in url:
            return url
        
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def parse_github_url(url: str) -> Optional[tuple[str, str]]:
    """
    Parse a GitHub URL into owner and repo name.
    
    Args:
        url: GitHub URL (HTTPS or SSH format)
    
    Returns:
        Tuple of (owner, repo) or None if parsing fails
    """
    try:
        return parse_repo_arg(url)
    except ValueError:
        return None


def scan_local_folder(
    root_path: str,
    github_token: Optional[str],
    affected_packages: dict[str, str],
    verbose: bool = False,
    max_depth: int = 5,
    default_branch_only: bool = False
) -> tuple[dict[str, list[ScanResult]], dict[str, list[SecurityWarning]], list[RepoAccessInfo]]:
    """
    Scan all git repositories under a local folder.

    Args:
        root_path: Path to the root folder to scan
        github_token: GitHub API token
        affected_packages: Dict of known malicious packages
        verbose: Enable verbose output
        max_depth: Maximum directory depth to search
        default_branch_only: Only scan the default branch (main/master)

    Returns:
        Tuple of (results_dict, warnings_dict, access_info_list) mapping repo names to their findings
    """
    all_results = {}
    all_warnings = {}
    all_access_info = []

    print(f"🔍 Searching for git repositories in: {root_path}")
    git_repos = find_git_repos(root_path, max_depth=max_depth)

    if not git_repos:
        print("  No git repositories found.")
        return all_results, all_warnings, all_access_info

    print(f"  Found {len(git_repos)} git repository(ies)\n")

    # Filter to only GitHub repos
    github_repos = []
    for repo_path in git_repos:
        url = get_github_remote_url(repo_path)
        if url:
            parsed = parse_github_url(url)
            if parsed:
                github_repos.append((repo_path, parsed[0], parsed[1]))
            else:
                print(f"  ⚠️  Could not parse GitHub URL: {url}")
        else:
            print(f"  ⏭️  Skipping (not a GitHub repo): {repo_path.name}")

    if not github_repos:
        print("\nNo GitHub repositories found.")
        return all_results, all_warnings, all_access_info

    print(f"\n📦 Found {len(github_repos)} GitHub repository(ies) to scan:\n")
    for repo_path, owner, repo in github_repos:
        print(f"  • {owner}/{repo} ({repo_path})")

    print("\n" + "=" * 60)

    # Scan each GitHub repo
    for i, (repo_path, owner, repo) in enumerate(github_repos, 1):
        print(f"\n[{i}/{len(github_repos)}] Scanning {owner}/{repo}...")
        print("-" * 50)

        try:
            scanner = RepoScanner(owner, repo, github_token, verbose=verbose)
            scanner.affected_packages = affected_packages

            # Quick access check
            if not scanner.check_access():
                print(f"  ❌ Cannot access repository")
                continue

            results, warnings = scanner.scan_all(include_branches=True, include_prs=True,
                                                  default_branch_only=default_branch_only)

            repo_name = f"{owner}/{repo}"
            if results:
                all_results[repo_name] = results
                print_results(results)
            else:
                print("\n  ✅ No malicious packages detected")

            if warnings:
                all_warnings[repo_name] = warnings
                print_security_warnings(warnings, repo_name)

            # Fetch repository access information
            try:
                access_info = scanner.get_access_info()
                all_access_info.append(access_info)
            except Exception as e:
                print(f"  ⚠️  Could not fetch access info: {e}")

        except Exception as e:
            print(f"  ❌ Error scanning: {e}")

    return all_results, all_warnings, all_access_info


def main():
    parser = argparse.ArgumentParser(
        description="Scan GitHub repositories for known malicious npm packages and security issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single repository
  %(prog)s --repo owner/repo-name
  %(prog)s --repo https://github.com/owner/repo-name --github-token ghp_xxxx

  # Scan only branches or PRs
  %(prog)s --repo owner/repo --branches-only
  %(prog)s --repo owner/repo --prs-only --output results.json

  # Scan all git repos in a local folder
  %(prog)s --local-path ~/projects --github-token ghp_xxxx
  %(prog)s --local-path /code/repos --github-token ghp_xxxx --output results.json

  # Suppress security recommendations
  %(prog)s --repo owner/repo --quiet

Security Hygiene (always enabled):
  • Non-pinned dependencies in package.json
  • Missing lock files
  • Lockfile injection detection
  • Dependency bot configuration analysis
        """
    )

    # Repository source (mutually exclusive)
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--repo",
        type=str,
        help="GitHub repository or comma-separated list (owner/repo,owner/repo2 or full URLs)"
    )
    source_group.add_argument(
        "--local-path",
        type=str,
        help="Local folder path to scan for git repositories"
    )

    parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Maximum depth to search for git repos when using --local-path (default: 5)"
    )
    parser.add_argument(
        "--github-token",
        type=str,
        help="GitHub personal access token (recommended for higher rate limits)"
    )
    parser.add_argument(
        "--branches-only",
        action="store_true",
        help="Only scan branches, not PRs"
    )
    parser.add_argument(
        "--prs-only",
        action="store_true",
        help="Only scan open PRs, not branches"
    )
    parser.add_argument(
        "--default-branch-only",
        action="store_true",
        help="Only scan the default branch (main/master), skip all other branches and PRs"
    )
    parser.add_argument(
        "--malicious-list-url",
        type=str,
        help="Custom URL for the malicious packages CSV"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Export results to JSON file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug output"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress general security recommendations at end"
    )
    parser.add_argument(
        "--list-lock-files",
        action="store_true",
        help="Just list where dependency files are found (on default branch), don't scan"
    )

    args = parser.parse_args()

    print(f"🔍 NPM Malicious Package Scanner")
    print()

    # Handle local folder scanning
    if args.local_path:
        # Load malicious packages first
        print("Loading malicious package list...")
        if args.malicious_list_url:
            affected_packages = fetch_affected_packages(args.malicious_list_url)
        else:
            affected_packages = fetch_affected_packages()
        print(f"Loaded {len(affected_packages)} known malicious packages\n")

        # Scan local folder
        all_results, all_warnings, all_access_info = scan_local_folder(
            args.local_path,
            args.github_token,
            affected_packages,
            verbose=args.verbose,
            max_depth=args.max_depth,
            default_branch_only=args.default_branch_only
        )

        # Summary
        print("\n" + "=" * 60)
        print("📊 SUMMARY")
        print("=" * 60)

        total_matches = sum(len(r) for r in all_results.values())
        total_warnings = sum(len(w) for w in all_warnings.values())

        if total_matches:
            print(f"\n⚠️  Found {total_matches} malicious package match(es) across {len(all_results)} repo(s):")
            for repo_name, results in all_results.items():
                print(f"  • {repo_name}: {len(results)} match(es)")
        else:
            print("\n✅ No malicious packages detected in any repository!")

        if total_warnings:
            # Count warnings by type
            unpinned_count = sum(1 for ws in all_warnings.values() for w in ws if w.warning_type == 'unpinned_dependency')
            missing_lock_count = sum(1 for ws in all_warnings.values() for w in ws if w.warning_type == 'missing_lock_file')
            injection_count = sum(1 for ws in all_warnings.values() for w in ws if w.warning_type == 'lockfile_injection')
            bot_count = sum(1 for ws in all_warnings.values() for w in ws if w.warning_type == 'dependency_bot')

            print(f"\nSecurity warnings found:")
            if unpinned_count:
                print(f"  • {unpinned_count} non-pinned dependencies")
            if missing_lock_count:
                print(f"  • {missing_lock_count} missing lock files")
            if injection_count:
                print(f"  • {injection_count} suspicious lockfile entries")
            if bot_count:
                print(f"  • {bot_count} dependency bot configs to review")

        # Export combined results
        if args.output:
            combined_results = []
            combined_warnings = []
            for repo_name, results in all_results.items():
                combined_results.extend(results)
            for repo_name, warnings in all_warnings.items():
                combined_warnings.extend(warnings)
            export_json(combined_results, combined_warnings, args.output, all_access_info)

        # Print general recommendations at the end (once)
        print_security_recommendations(quiet=args.quiet)

        sys.exit(1 if total_matches else 0)

    # Handle repo scanning (single or multiple)
    # Parse comma-separated repos
    repo_args = [r.strip() for r in args.repo.split(',') if r.strip()]

    repos_to_scan = []
    for repo_arg in repo_args:
        try:
            owner, repo = parse_repo_arg(repo_arg)
            repos_to_scan.append((owner, repo))
        except ValueError as e:
            parser.error(str(e))

    # Determine what to scan
    include_branches = not args.prs_only
    include_prs = not args.branches_only
    default_branch_only = args.default_branch_only

    if default_branch_only and (args.branches_only or args.prs_only):
        parser.error("Cannot use --default-branch-only with --branches-only or --prs-only")

    if not include_branches and not include_prs:
        parser.error("Cannot use both --branches-only and --prs-only")

    # If just listing lock files, do that for each repo and exit
    if args.list_lock_files:
        for owner, repo in repos_to_scan:
            print(f"\n{'=' * 60}")
            print(f"Repository: {owner}/{repo}")
            print("Searching for dependency files on default branch...")

            scanner = RepoScanner(owner, repo, args.github_token, verbose=args.verbose)
            branches = scanner.api.get_branches(owner, repo)
            if not branches:
                print("No branches found.")
                continue

            default_ref = branches[0]
            print(f"Using branch: {default_ref.name} ({default_ref.sha[:7]})")

            dep_files = scanner.api.find_dependency_files(owner, repo, default_ref.sha)
            if dep_files:
                lock_files = [f for f in dep_files if not f.endswith('package.json')]
                package_jsons = [f for f in dep_files if f.endswith('package.json')]

                print(f"\nFound {len(dep_files)} dependency file(s):")
                if lock_files:
                    print("\n  Lock files (exact versions):")
                    for lf in sorted(lock_files):
                        print(f"    📄 {lf}")
                if package_jsons:
                    print("\n  package.json files (version ranges):")
                    for pj in sorted(package_jsons):
                        print(f"    📦 {pj}")
            else:
                print("\n❌ No dependency files found")
                print("   This repo may not be an npm/Node.js project.")
        sys.exit(0)

    # Load malicious packages once
    print("Loading malicious package list...")
    if args.malicious_list_url:
        affected_packages = fetch_affected_packages(args.malicious_list_url)
    else:
        affected_packages = fetch_affected_packages()
    print(f"Loaded {len(affected_packages)} known malicious packages\n")

    # Track results across all repos
    all_results: dict[str, list[ScanResult]] = {}
    all_warnings: dict[str, list[SecurityWarning]] = {}
    all_access_info: list[RepoAccessInfo] = []

    # Scan each repository
    for i, (owner, repo) in enumerate(repos_to_scan, 1):
        repo_name = f"{owner}/{repo}"

        if len(repos_to_scan) > 1:
            print(f"\n{'=' * 60}")
            print(f"[{i}/{len(repos_to_scan)}] Scanning {repo_name}...")
            print("-" * 50)
        else:
            print(f"   Repository: {repo_name}")
            print()

        scanner = RepoScanner(owner, repo, args.github_token, verbose=args.verbose)
        scanner.affected_packages = affected_packages

        # Verify access first
        if not scanner.check_access():
            print(f"  ❌ Cannot access repository")
            continue
        print()

        results, warnings = scanner.scan_all(include_branches=include_branches, include_prs=include_prs,
                                             default_branch_only=default_branch_only)

        # Store results
        if results:
            all_results[repo_name] = results
            print_results(results)
        else:
            print("\n✅ No malicious packages detected!")

        if warnings:
            all_warnings[repo_name] = warnings
            print_security_warnings(warnings, repo_name)

        # Fetch repository access information
        if args.output:
            try:
                access_info = scanner.get_access_info()
                all_access_info.append(access_info)
            except Exception as e:
                print(f"\n⚠️  Could not fetch access info: {e}")

    # Summary for multiple repos
    if len(repos_to_scan) > 1:
        print("\n" + "=" * 60)
        print("📊 SUMMARY")
        print("=" * 60)

        total_matches = sum(len(r) for r in all_results.values())
        total_warnings = sum(len(w) for w in all_warnings.values())

        if total_matches:
            print(f"\n⚠️  Found {total_matches} malicious package match(es) across {len(all_results)} repo(s):")
            for repo_name, results in all_results.items():
                print(f"  • {repo_name}: {len(results)} match(es)")
        else:
            print("\n✅ No malicious packages detected in any repository!")

        if total_warnings:
            unpinned_count = sum(1 for ws in all_warnings.values() for w in ws if w.warning_type == 'unpinned_dependency')
            missing_lock_count = sum(1 for ws in all_warnings.values() for w in ws if w.warning_type == 'missing_lock_file')
            injection_count = sum(1 for ws in all_warnings.values() for w in ws if w.warning_type == 'lockfile_injection')
            bot_count = sum(1 for ws in all_warnings.values() for w in ws if w.warning_type == 'dependency_bot')

            print(f"\nSecurity warnings found:")
            if unpinned_count:
                print(f"  • {unpinned_count} non-pinned dependencies")
            if missing_lock_count:
                print(f"  • {missing_lock_count} missing lock files")
            if injection_count:
                print(f"  • {injection_count} suspicious lockfile entries")
            if bot_count:
                print(f"  • {bot_count} dependency bot configs to review")

    # Export combined results
    if args.output:
        combined_results = []
        combined_warnings = []
        for repo_name, results in all_results.items():
            combined_results.extend(results)
        for repo_name, warnings in all_warnings.items():
            combined_warnings.extend(warnings)
        export_json(combined_results, combined_warnings, args.output, all_access_info if all_access_info else None)

    # Print general recommendations at the end
    print_security_recommendations(quiet=args.quiet)

    # Exit with error code if matches found
    total_matches = sum(len(r) for r in all_results.values())
    sys.exit(1 if total_matches else 0)


if __name__ == "__main__":
    main()