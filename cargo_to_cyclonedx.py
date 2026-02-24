#!/usr/bin/env python3
"""
Convert Rust Cargo packages to CycloneDX 1.5 SBOM (JSON).

Extraction commands (run in Rust project directory):

  # Option A — Cargo.lock (recommended):
  cp Cargo.lock cargo_packages.txt

  # Option B — cargo metadata JSON:
  cargo metadata --format-version 1 --no-deps > cargo_packages.txt

  # Option C — simple list:
  cargo tree --depth 0 --prefix none 2>/dev/null | awk '{print $1"|"$2}' > cargo_packages.txt

Input formats (auto-detected):
  1) Cargo.lock (TOML-like)
  2) cargo metadata JSON
  3) Pipe-delimited: name|version

Usage:
  python3 cargo_to_cyclonedx.py -i Cargo.lock -o sbom.cdx.json
  python3 cargo_to_cyclonedx.py -i cargo_packages.txt -o sbom.cdx.json
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
    """Auto-detect the Cargo listing format.

    Distinguishes ``Cargo.lock`` (TOML-like), ``cargo metadata`` JSON,
    and pipe-delimited input.

    Args:
        content: Raw file content.

    Returns:
        One of ``'cargo-lock'``, ``'cargo-metadata'``, or ``'pipe'``.
    """
    stripped = content.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            if "packages" in data or "resolve" in data:
                return "cargo-metadata"
        except json.JSONDecodeError:
            pass
    if "[[package]]" in stripped or stripped.startswith("# This file is automatically"):
        return "cargo-lock"
    for line in stripped.splitlines()[:5]:
        if "|" in line:
            return "pipe"
    return "cargo-lock"


def parse_cargo_lock(content):
    """Parse a ``Cargo.lock`` file (TOML-like ``[[package]]`` blocks).

    Args:
        content: Raw Cargo.lock content.

    Returns:
        List of package dicts with ``name``, ``version``, ``source``,
        ``checksum`` keys.
    """
    packages = []
    current = {}
    for line in content.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if current.get("name") and current.get("version"):
                packages.append(current)
            current = {}
            continue
        m = re.match(r'^name\s*=\s*"([^"]+)"', line)
        if m:
            current["name"] = m.group(1)
            continue
        m = re.match(r'^version\s*=\s*"([^"]+)"', line)
        if m:
            current["version"] = m.group(1)
            continue
        m = re.match(r'^source\s*=\s*"([^"]+)"', line)
        if m:
            current["source"] = m.group(1)
            continue
        m = re.match(r'^checksum\s*=\s*"([^"]+)"', line)
        if m:
            current["checksum"] = m.group(1)
            continue

    # Last entry
    if current.get("name") and current.get("version"):
        packages.append(current)

    return packages


def parse_cargo_metadata(content):
    """Parse ``cargo metadata --format-version=1`` JSON output.

    Args:
        content: JSON string from ``cargo metadata``.

    Returns:
        List of package dicts.
    """
    data = json.loads(content)
    packages = []
    seen = set()
    for pkg in data.get("packages", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        key = f"{name}@{version}"
        if key not in seen and name and version:
            seen.add(key)
            packages.append({
                "name": name,
                "version": version,
                "source": pkg.get("source", ""),
                "checksum": "",
            })
    return packages


def parse_pipe_format(content):
    """Parse pipe-delimited Cargo data: ``name|version``.

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
            version = parts[1].strip().lstrip("v")
            packages.append({
                "name": parts[0].strip(),
                "version": version,
                "source": "",
                "checksum": "",
            })
    return packages


def build_purl(pkg):
    """Build a ``pkg:cargo/`` PURL for a crates.io package.

    Args:
        pkg: Parsed package dict.

    Returns:
        A PURL string.
    """
    return f"pkg:cargo/{pkg['name']}@{pkg['version']}"


def build_component(pkg):
    """Build a CycloneDX ``library`` component from parsed Cargo data.

    Args:
        pkg: Parsed package dict.

    Returns:
        A CycloneDX component dict with Trivy ``cargo`` type.
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
        {"name": "aquasecurity:trivy:PkgType", "value": "cargo"},
    ]

    if pkg.get("source"):
        properties.append({"name": "cargo:source", "value": pkg["source"]})
    if pkg.get("checksum"):
        properties.append({"name": "cargo:checksum", "value": pkg["checksum"]})

    component["properties"] = properties

    return component, purl


def generate_sbom(packages, rust_version=None, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM document for Cargo packages.

    Args:
        packages:     List of parsed package dicts.
        rust_version: Optional Rust version for metadata.
        serial_number: Optional URN UUID; auto-generated if ``None``.

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    description = "Rust crates (Cargo)"
    if rust_version:
        description = f"{description} — Rust {rust_version}"

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
                    "name": "cargo-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "rust-crates",
                "version": rust_version or "",
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
        description="Convert Cargo.lock/metadata to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input: Cargo.lock, cargo metadata JSON, or pipe-delimited (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--rust-version", default=None,
                        help="Rust version (informational)")
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

    if fmt == "cargo-lock":
        packages = parse_cargo_lock(content)
    elif fmt == "cargo-metadata":
        packages = parse_cargo_metadata(content)
    else:
        packages = parse_pipe_format(content)

    sbom = generate_sbom(packages, rust_version=args.rust_version)

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
