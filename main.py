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
        data = self._request(f"/repos/{owner}/{repo}/contents/{path}?ref={ref}")
        if data is None or isinstance(data, list):
            return None
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode('utf-8')
        return None


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
    
    def scan_ref(self, ref: RefInfo, show_progress: bool = True) -> list[ScanResult]:
        """Scan a single ref (branch or PR) for malicious packages."""
        results = []
        
        # Find all dependency files in this ref
        dep_files = self.api.find_dependency_files(self.owner, self.repo, ref.sha)
        
        if not dep_files:
            if show_progress:
                print("(no dependency files)")
            return results
        
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
            if file_path.endswith("package-lock.json"):
                parser = parse_package_lock_json
            elif file_path.endswith("yarn.lock"):
                parser = parse_yarn_lock
            elif file_path.endswith("pnpm-lock.yaml"):
                parser = parse_pnpm_lock
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
        
        return results
    
    def scan_all(self, include_branches: bool = True, include_prs: bool = True) -> list[ScanResult]:
        """Scan all branches and/or PRs in the repository."""
        all_results = []
        refs_to_scan = []
        
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
            return all_results
        
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
        
        print(f"\nScanning {len(refs_to_scan)} refs...")
        
        for i, ref in enumerate(refs_to_scan, 1):
            print(f"  [{i}/{len(refs_to_scan)}] {ref.ref_type}: {ref.name[:50]}... ", end="")
            results = self.scan_ref(ref, show_progress=True)
            if results:
                print(f"⚠️  {len(results)} match(es)!")
            else:
                print("✓ clean")
            all_results.extend(results)
        
        return all_results


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


def export_json(results: list[ScanResult], filepath: str):
    """Export results to JSON file."""
    data = [
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
    ]
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"\nResults exported to: {filepath}")


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
    max_depth: int = 5
) -> dict[str, list[ScanResult]]:
    """
    Scan all git repositories under a local folder.
    
    Args:
        root_path: Path to the root folder to scan
        github_token: GitHub API token
        affected_packages: Dict of known malicious packages
        verbose: Enable verbose output
        max_depth: Maximum directory depth to search
    
    Returns:
        Dict mapping repo paths to their scan results
    """
    all_results = {}
    
    print(f"🔍 Searching for git repositories in: {root_path}")
    git_repos = find_git_repos(root_path, max_depth=max_depth)
    
    if not git_repos:
        print("  No git repositories found.")
        return all_results
    
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
        return all_results
    
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
            
            results = scanner.scan_all(include_branches=True, include_prs=True)
            
            if results:
                all_results[f"{owner}/{repo}"] = results
                print_results(results)
            else:
                print("\n  ✅ No malicious packages detected")
                
        except Exception as e:
            print(f"  ❌ Error scanning: {e}")
    
    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="Scan GitHub repositories for known malicious npm packages.",
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
        """
    )
    
    # Repository source (mutually exclusive)
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--repo",
        type=str,
        help="GitHub repository (owner/repo or full URL)"
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
        all_results = scan_local_folder(
            args.local_path,
            args.github_token,
            affected_packages,
            verbose=args.verbose,
            max_depth=args.max_depth
        )
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 SUMMARY")
        print("=" * 60)
        
        total_matches = sum(len(r) for r in all_results.values())
        if total_matches:
            print(f"\n⚠️  Found {total_matches} malicious package match(es) across {len(all_results)} repo(s):")
            for repo_name, results in all_results.items():
                print(f"  • {repo_name}: {len(results)} match(es)")
        else:
            print("\n✅ No malicious packages detected in any repository!")
        
        # Export combined results
        if args.output:
            combined_results = []
            for repo_name, results in all_results.items():
                for r in results:
                    combined_results.append(r)
            export_json(combined_results, args.output)
        
        sys.exit(1 if total_matches else 0)
    
    # Handle single repo scanning
    try:
        owner, repo = parse_repo_arg(args.repo)
    except ValueError as e:
        parser.error(str(e))
    
    print(f"   Repository: {owner}/{repo}")
    print()
    
    # Determine what to scan
    include_branches = not args.prs_only
    include_prs = not args.branches_only
    
    if not include_branches and not include_prs:
        parser.error("Cannot use both --branches-only and --prs-only")
    
    # Create scanner and run
    scanner = RepoScanner(owner, repo, args.github_token, verbose=args.verbose)
    
    # Verify access first
    if not scanner.check_access():
        sys.exit(1)
    print()
    
    # If just listing lock files, do that and exit
    if args.list_lock_files:
        print("Searching for dependency files on default branch...")
        # Get default branch
        branches = scanner.api.get_branches(owner, repo)
        if not branches:
            print("No branches found.")
            sys.exit(1)
        
        # Use first branch (usually main/master)
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
    
    scanner.load_affected_packages(args.malicious_list_url)
    
    results = scanner.scan_all(include_branches=include_branches, include_prs=include_prs)
    
    # Output results
    print_results(results)
    
    if args.output:
        export_json(results, args.output)
    
    # Exit with error code if matches found
    sys.exit(1 if results else 0)


if __name__ == "__main__":
    main()