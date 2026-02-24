#!/usr/bin/env python3
"""
Convert Go module listing to CycloneDX 1.5 SBOM (JSON).

Extraction commands (run in project directory or on target host):

  # Option A — from a Go project (go.sum):
  cp go.sum go_packages.txt

  # Option B — go list modules:
  go list -m all 2>/dev/null > go_packages.txt

  # Option C — from compiled binary (requires Go 1.18+):
  go version -m /path/to/binary > go_packages.txt

Input formats (auto-detected):
  1) go.sum:  module v1.2.3 h1:hash=
  2) go list -m all:  module v1.2.3
  3) go version -m:  dep  module  v1.2.3  h1:hash=
  4) Pipe-delimited: module|version

Usage:
  python3 go_to_cyclonedx.py -i go.sum -o sbom.cdx.json
  python3 go_to_cyclonedx.py -i go_packages.txt -o sbom.cdx.json
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
    """Auto-detect the Go module listing format.

    Distinguishes ``go.sum``, ``go list -m all``, ``go version -m``,
    and pipe-delimited input.

    Args:
        content: Raw file content.

    Returns:
        One of ``'go-sum'``, ``'go-list'``, ``'go-version-m'``, or ``'pipe'``.
    """
    lines = content.strip().splitlines()
    for line in lines[:20]:
        line = line.strip()
        if not line:
            continue
        # go.sum: "module v1.2.3 h1:..." or "module v1.2.3/go.mod h1:..."
        if re.match(r"^\S+\s+v\S+\s+h1:", line):
            return "go-sum"
        if re.match(r"^\S+\s+v\S+/go\.mod\s+h1:", line):
            return "go-sum"
        # go version -m output: "path\t...", "mod\t...", "dep\t..."
        if line.startswith("dep\t") or line.startswith("mod\t") or line.startswith("path\t"):
            return "go-version-m"
        if re.match(r"^\s+dep\s+", line) or re.match(r"^\s+mod\s+", line):
            return "go-version-m"
        # go list -m all: "module v1.2.3"
        if re.match(r"^\S+\s+v\d+\.\d+", line):
            return "go-list"
        if "|" in line:
            return "pipe"
    return "go-list"


def parse_go_sum(content):
    """Parse a ``go.sum`` file.

    De-duplicates entries (``go.sum`` contains ``/go.mod`` suffixed lines).

    Args:
        content: Raw go.sum content.

    Returns:
        List of package dicts with ``module`` and ``version`` keys.
    """
    packages = {}
    for line in content.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            module = parts[0]
            version = parts[1].split("/go.mod")[0]  # Strip /go.mod suffix
            if module and version.startswith("v"):
                key = f"{module}@{version}"
                if key not in packages:
                    packages[key] = {"name": module, "version": version}
    return list(packages.values())


def parse_go_list(content):
    """Parse ``go list -m all`` output.

    Args:
        content: Raw output from ``go list -m all``.

    Returns:
        List of package dicts.
    """
    packages = []
    seen = set()
    for line in content.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            module = parts[0]
            version = parts[1]
            # Skip replacements (=> lines) and the main module (no version)
            if "=>" in line:
                continue
            if version.startswith("v"):
                key = f"{module}@{version}"
                if key not in seen:
                    seen.add(key)
                    packages.append({"name": module, "version": version})
    return packages


def parse_go_version_m(content):
    """Parse ``go version -m`` binary inspection output.

    Args:
        content: Raw output from ``go version -m <binary>``.

    Returns:
        List of package dicts.
    """
    packages = []
    seen = set()
    for line in content.strip().splitlines():
        line = line.strip()
        # Match "dep\tmodule\tversion\thash" or whitespace-separated
        m = re.match(r"(?:dep|mod)\s+(\S+)\s+(v\S+)", line)
        if m:
            module = m.group(1)
            version = m.group(2)
            key = f"{module}@{version}"
            if key not in seen:
                seen.add(key)
                packages.append({"name": module, "version": version})
    return packages


def parse_pipe_format(content):
    """Parse pipe-delimited Go module data: ``module|version``.

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
    """Build a ``pkg:golang/`` PURL for a Go module.

    Args:
        pkg: Parsed package dict with ``module`` and ``version`` keys.

    Returns:
        A PURL string.
    """
    # PURL: pkg:golang/module@version
    # Encode slashes in module path
    module = pkg["name"]
    version = pkg["version"]
    return f"pkg:golang/{module}@{version}"


def build_component(pkg):
    """Build a CycloneDX ``library`` component from parsed Go module data.

    Args:
        pkg: Parsed package dict.

    Returns:
        A CycloneDX component dict with Trivy ``gomod`` type.
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
        {"name": "aquasecurity:trivy:PkgType", "value": "gomod"},
    ]
    component["properties"] = properties

    return component, purl


def generate_sbom(packages, go_version=None, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM document for Go modules.

    Args:
        packages:   List of parsed module dicts.
        go_version: Optional Go version for metadata.
        serial_number: Optional URN UUID; auto-generated if ``None``.

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    description = "Go modules"
    if go_version:
        description = f"{description} — Go {go_version}"

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
                    "name": "go-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "go-modules",
                "version": go_version or "",
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
        description="Convert Go module listing to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input: go.sum, go list -m all, go version -m, or pipe-delimited (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--go-version", default=None,
                        help="Go version (informational)")
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

    if fmt == "go-sum":
        packages = parse_go_sum(content)
    elif fmt == "go-version-m":
        packages = parse_go_version_m(content)
    elif fmt == "pipe":
        packages = parse_pipe_format(content)
    else:
        packages = parse_go_list(content)

    sbom = generate_sbom(packages, go_version=args.go_version)

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
