#!/usr/bin/env python3
"""
Convert PHP Composer packages to CycloneDX 1.5 SBOM (JSON).

Extraction commands (run in PHP project directory):

  # Option A — composer.lock (recommended):
  cp composer.lock composer_packages.txt

  # Option B — composer show:
  composer show --locked --format=json > composer_packages.txt

  # Option C — simple list:
  composer show --locked --no-interaction 2>/dev/null | awk '{print $1"|"$2}' > composer_packages.txt

Input formats (auto-detected):
  1) composer.lock JSON
  2) composer show --format=json
  3) Pipe-delimited: vendor/package|version

Usage:
  python3 composer_to_cyclonedx.py -i composer.lock -o sbom.cdx.json
  python3 composer_to_cyclonedx.py -i composer_packages.txt -o sbom.cdx.json
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
    """Auto-detect the Composer listing format.

    Distinguishes ``composer.lock``, ``composer show --format=json``,
    and pipe-delimited input.

    Args:
        content: Raw file content.

    Returns:
        One of ``'composer-lock'``, ``'composer-show'``, or ``'pipe'``.
    """
    stripped = content.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            if "packages" in data and isinstance(data["packages"], list):
                # Both composer.lock and composer show --format=json have packages[]
                if "content-hash" in data or "_readme" in data:
                    return "composer-lock"
                return "composer-show-json"
            if "installed" in data:
                return "composer-show-json"
        except json.JSONDecodeError:
            pass
    for line in stripped.splitlines()[:5]:
        if "|" in line:
            return "pipe"
    return "composer-lock"


def parse_composer_lock(content):
    """Parse a ``composer.lock`` file.

    Extracts both ``packages`` and ``packages-dev`` sections.

    Args:
        content: JSON string of the lock file.

    Returns:
        List of package dicts.
    """
    data = json.loads(content)
    packages = []
    seen = set()

    for pkg_list_key in ("packages", "packages-dev"):
        for pkg in data.get(pkg_list_key, []):
            name = pkg.get("name", "")
            version = pkg.get("version", "").lstrip("v")
            key = f"{name}@{version}"
            if key in seen or not name or not version:
                continue
            seen.add(key)

            license_list = pkg.get("license", [])
            packages.append({
                "name": name,
                "version": version,
                "description": pkg.get("description", ""),
                "homepage": pkg.get("homepage", ""),
                "license": license_list[0] if license_list else "",
                "source_type": pkg.get("source", {}).get("type", ""),
                "source_url": pkg.get("source", {}).get("url", ""),
                "dev": pkg_list_key == "packages-dev",
            })

    return packages


def parse_composer_show_json(content):
    """Parse ``composer show --format=json`` output.

    Args:
        content: JSON string from ``composer show``.

    Returns:
        List of package dicts.
    """
    data = json.loads(content)
    packages = []
    seen = set()

    pkg_list = data.get("installed", data.get("packages", []))
    for pkg in pkg_list:
        name = pkg.get("name", "")
        version = (pkg.get("version") or pkg.get("versions", [""])[0] or "").lstrip("v")
        key = f"{name}@{version}"
        if key in seen or not name or not version:
            continue
        seen.add(key)
        packages.append({
            "name": name,
            "version": version,
            "description": pkg.get("description", ""),
            "homepage": pkg.get("homepage", ""),
            "license": "",
            "source_type": "",
            "source_url": "",
            "dev": False,
        })

    return packages


def parse_pipe_format(content):
    """Parse pipe-delimited Composer data: ``name|version``.

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
                "description": "",
                "homepage": "",
                "license": "",
                "source_type": "",
                "source_url": "",
                "dev": False,
            })
    return packages


def build_purl(pkg):
    """Build a ``pkg:composer/`` PURL for a Packagist package.

    Uses the ``vendor/package`` naming convention with ``%2F``-encoded
    separators when needed.

    Args:
        pkg: Parsed package dict.

    Returns:
        A PURL string.
    """
    # Composer packages are vendor/name
    name = pkg["name"]
    encoded = name.replace("/", "%2F") if "/" in name else name
    return f"pkg:composer/{encoded}@{pkg['version']}"


def build_component(pkg):
    """Build a CycloneDX ``library`` component from parsed Composer data.

    Args:
        pkg: Parsed package dict.

    Returns:
        A CycloneDX component dict with Trivy ``composer`` type.
    """
    purl = build_purl(pkg)
    bom_ref = hashlib.sha256(purl.encode()).hexdigest()[:16]

    # For display, use the full vendor/package name
    group = ""
    name = pkg["name"]
    if "/" in name:
        parts = name.split("/", 1)
        group = parts[0]
        name = parts[1]

    component = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": purl,
    }

    if group:
        component["group"] = group

    if pkg.get("description"):
        component["description"] = pkg["description"]

    if pkg.get("license"):
        component["licenses"] = [{"license": {"id": pkg["license"]}}]

    properties = [
        {"name": "aquasecurity:trivy:PkgType", "value": "composer"},
    ]
    if pkg.get("dev"):
        properties.append({"name": "composer:dev", "value": "true"})

    component["properties"] = properties

    external_refs = []
    if pkg.get("homepage"):
        external_refs.append({"url": pkg["homepage"], "type": "website"})
    if pkg.get("source_url"):
        external_refs.append({"url": pkg["source_url"], "type": "vcs"})
    if external_refs:
        component["externalReferences"] = external_refs

    return component, purl


def generate_sbom(packages, php_version=None, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM for PHP Composer packages.

    Args:
        packages:    List of parsed package dicts.
        php_version: Optional PHP version for metadata.
        serial_number: Optional URN UUID; auto-generated if ``None``.

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    description = "PHP Composer packages"
    if php_version:
        description = f"{description} — PHP {php_version}"

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
                    "name": "composer-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "composer-packages",
                "version": php_version or "",
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
        description="Convert Composer lock/show to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input: composer.lock, composer show JSON, or pipe-delimited (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--php-version", default=None,
                        help="PHP version (informational)")
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

    if fmt == "composer-lock":
        packages = parse_composer_lock(content)
    elif fmt == "composer-show-json":
        packages = parse_composer_show_json(content)
    else:
        packages = parse_pipe_format(content)

    sbom = generate_sbom(packages, php_version=args.php_version)

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
