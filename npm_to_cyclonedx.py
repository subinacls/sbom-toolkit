#!/usr/bin/env python3
"""
Convert npm/yarn package listing to CycloneDX 1.5 SBOM (JSON).

Extraction commands (run on target host or in project directory):

  # Option A — npm global packages:
  npm list -g --json > npm_packages.txt

  # Option B — npm project packages:
  npm list --json --all > npm_packages.txt

  # Option C — package-lock.json (from a project):
  cp package-lock.json npm_packages.txt

  # Option D — yarn.lock:
  cp yarn.lock npm_packages.txt

  # Option E — simple flat list:
  npm list -g --depth=0 --parseable 2>/dev/null | tail -n +2 | xargs -I{} basename {} | \
    sed 's/@/|/' > npm_packages.txt
  # produces: name|version

Input formats (auto-detected):
  1) npm list --json output
  2) package-lock.json (lockfileVersion 1, 2, or 3)
  3) yarn.lock
  4) Pipe-delimited: name|version

Usage:
  python3 npm_to_cyclonedx.py -i npm_packages.txt -o sbom.cdx.json
  python3 npm_to_cyclonedx.py -i package-lock.json -o sbom.cdx.json
  python3 npm_to_cyclonedx.py -i yarn.lock -o sbom.cdx.json
"""

__version__ = "1.0.0"
__author__ = "SBOM Toolkit Contributors"
__license__ = "MIT"

import json
import sys
import re
import uuid
import hashlib
import argparse
from datetime import datetime, timezone


def detect_format(content):
    """Auto-detect the npm/yarn package listing format.

    Distinguishes ``npm list --json``, ``package-lock.json``,
    ``yarn.lock``, and pipe-delimited input.

    Args:
        content: Raw file content.

    Returns:
        One of ``'npm-json'``, ``'package-lock'``, ``'yarn-lock'``, or ``'pipe'``.
    """
    stripped = content.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            if "lockfileVersion" in data:
                return "package-lock"
            if "dependencies" in data or "name" in data:
                return "npm-json"
        except json.JSONDecodeError:
            pass
    # yarn.lock detection
    if "# yarn lockfile" in stripped[:200] or re.search(r'^"\S+@.+":', stripped[:500], re.MULTILINE):
        return "yarn-lock"
    # Pipe-delimited
    for line in stripped.splitlines()[:5]:
        if "|" in line:
            return "pipe"
    return "pipe"


def parse_npm_json(content):
    """Parse ``npm list --json`` output (recursive dependency tree).

    Args:
        content: JSON string from ``npm list --json``.

    Returns:
        List of package dicts.
    """
    data = json.loads(content)
    packages = []
    seen = set()

    def walk_deps(deps):
        if not deps:
            return
        for name, info in deps.items():
            version = info.get("version", "")
            key = f"{name}@{version}"
            if key not in seen and version:
                seen.add(key)
                packages.append({"name": name, "version": version})
            walk_deps(info.get("dependencies", {}))

    walk_deps(data.get("dependencies", {}))
    return packages


def parse_package_lock(content):
    """Parse ``package-lock.json`` (supports lockfile versions 1, 2, and 3).

    Args:
        content: JSON string of the lock file.

    Returns:
        List of package dicts.
    """
    data = json.loads(content)
    packages = []
    seen = set()

    # lockfileVersion 2/3: "packages" field with "" as root
    if "packages" in data:
        for path, info in data["packages"].items():
            if path == "":
                continue  # Skip root project
            # Path like "node_modules/express" or "node_modules/@scope/name"
            name = info.get("name", "")
            if not name:
                # Infer from path
                parts = path.split("node_modules/")
                name = parts[-1] if parts else path
            version = info.get("version", "")
            key = f"{name}@{version}"
            if key not in seen and version:
                seen.add(key)
                packages.append({"name": name, "version": version})

    # lockfileVersion 1: "dependencies" field
    elif "dependencies" in data:
        def walk(deps):
            for name, info in deps.items():
                version = info.get("version", "")
                key = f"{name}@{version}"
                if key not in seen and version:
                    seen.add(key)
                    packages.append({"name": name, "version": version})
                walk(info.get("dependencies", {}))
        walk(data["dependencies"])

    return packages


def parse_yarn_lock(content):
    """Parse ``yarn.lock`` v1 format.

    Args:
        content: Raw yarn.lock content.

    Returns:
        List of package dicts with scoped-package support.
    """
    packages = []
    seen = set()

    # Match entries like:
    # "package@^1.0.0", "package@~2.0.0":
    #   version "1.2.3"
    current_names = []
    for line in content.splitlines():
        # New entry: "name@version-range":
        m = re.match(r'^"?(@?[^@\s"]+)@[^"]*"?', line)
        if m and not line.startswith(" "):
            current_names = []
            # May have multiple comma-separated specifiers
            specs = re.findall(r'"?(@?[^@\s",]+)@', line)
            current_names = list(set(specs))
        # Version line
        vm = re.match(r'^\s+version\s+"([^"]+)"', line)
        if vm and current_names:
            version = vm.group(1)
            for name in current_names:
                key = f"{name}@{version}"
                if key not in seen:
                    seen.add(key)
                    packages.append({"name": name, "version": version})
            current_names = []

    return packages


def parse_pipe_format(content):
    """Parse pipe-delimited npm data: ``name|version``.

    Args:
        content: Raw pipe-delimited content.

    Returns:
        List of package dicts.
    """
    packages = []
    for line in content.strip().splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|", 1)
        if len(parts) == 2 and parts[0].strip() and parts[1].strip():
            packages.append({
                "name": parts[0].strip(),
                "version": parts[1].strip(),
            })
    return packages


def build_purl(pkg):
    """Build a ``pkg:npm/`` PURL for an npm package.

    Handles scoped packages (``@scope/name``) by URL-encoding the ``@``.

    Args:
        pkg: Parsed package dict.

    Returns:
        A PURL string.
    """
    name = pkg["name"]
    version = pkg["version"]
    # Scoped packages: @scope/name → pkg:npm/%40scope/name@version
    if name.startswith("@"):
        return f"pkg:npm/%40{name[1:]}@{version}"
    return f"pkg:npm/{name}@{version}"


def build_component(pkg):
    """Build a CycloneDX ``library`` component from parsed npm data.

    Args:
        pkg: Parsed package dict.

    Returns:
        A CycloneDX component dict.
    """
    purl = build_purl(pkg)
    bom_ref = hashlib.sha256(purl.encode()).hexdigest()[:16]

    component = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": purl,
    }

    properties = [
        {"name": "aquasecurity:trivy:PkgType", "value": "node-pkg"},
    ]
    component["properties"] = properties

    return component, purl


def generate_sbom(packages, node_version=None, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM document for npm packages.

    Args:
        packages:     List of parsed package dicts.
        node_version: Optional Node.js version for metadata.
        serial_number: Optional URN UUID; auto-generated if ``None``.

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    description = "Node.js packages (npm)"
    if node_version:
        description = f"{description} — Node {node_version}"

    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "custom",
                    "name": "npm-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "node-packages",
                "version": node_version or "",
                "description": description,
                "properties": [
                    {"name": "aquasecurity:trivy:Class", "value": "lang-pkgs"},
                ],
            },
        },
        "components": [],
    }

    seen_purls = set()
    for pkg in packages:
        component, purl = build_component(pkg)
        if purl not in seen_purls:
            seen_purls.add(purl)
            sbom["components"].append(component)

    return sbom


def main():
    parser = argparse.ArgumentParser(
        description="Convert npm/yarn package listing to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input: npm list --json, package-lock.json, yarn.lock, or pipe-delimited (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--node-version", default=None,
                        help="Node.js version (informational)")
    args = parser.parse_args()

    if args.input == "-":
        content = sys.stdin.read()
    else:
        with open(args.input, "r") as f:
            content = f.read()

    content = content.strip()
    if not content:
        print("ERROR: Empty input", file=sys.stderr)
        sys.exit(1)

    fmt = detect_format(content)
    print(f"Detected input format: {fmt}", file=sys.stderr)

    if fmt == "npm-json":
        packages = parse_npm_json(content)
    elif fmt == "package-lock":
        packages = parse_package_lock(content)
    elif fmt == "yarn-lock":
        packages = parse_yarn_lock(content)
    else:
        packages = parse_pipe_format(content)

    sbom = generate_sbom(packages, node_version=args.node_version)

    output_json = json.dumps(sbom, indent=2)
    if args.output == "-":
        print(output_json)
    else:
        with open(args.output, "w") as f:
            f.write(output_json)
            f.write("\n")
        print(f"SBOM written to {args.output} — {len(sbom['components'])} components",
              file=sys.stderr)


if __name__ == "__main__":
    main()
