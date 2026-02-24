#!/usr/bin/env python3
"""
Convert .NET/NuGet packages to CycloneDX 1.5 SBOM (JSON).

Extraction commands:

  # Option A — dotnet list package (recommended):
  dotnet list package --format json > nuget_packages.txt

  # Option B — packages.lock.json (from project dir):
  cp packages.lock.json nuget_packages.txt

  # Option C — dotnet list package (text output):
  dotnet list package > nuget_packages.txt

  # Option D — paket.lock (Paket package manager):
  cp paket.lock nuget_packages.txt

  # Option E — pipe-delimited (manual):
  echo "PackageName|Version" >> nuget_packages.txt

Input formats (auto-detected):
  1) dotnet list package --format json
  2) packages.lock.json
  3) dotnet list package (text output)
  4) paket.lock
  5) Pipe-delimited: PackageName|Version

Usage:
  python3 nuget_to_cyclonedx.py -i nuget_packages.txt -o sbom.cdx.json
  dotnet list package | python3 nuget_to_cyclonedx.py -o sbom.cdx.json
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
    """Auto-detect the NuGet listing format.

    Distinguishes ``dotnet list package --format json``, ``packages.lock.json``,
    ``dotnet list package`` text, ``paket.lock``, and pipe-delimited input.

    Args:
        content: Raw file content.

    Returns:
        One of ``'dotnet-json'``, ``'packages-lock'``, ``'dotnet-text'``,
        ``'paket-lock'``, or ``'pipe'``.
    """
    stripped = content.strip()

    # JSON formats
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            # dotnet list package --format json
            if "projects" in data or "version" in data and "parameters" in data:
                return "dotnet-json"
            # packages.lock.json
            if "dependencies" in data:
                return "packages-lock"
        except json.JSONDecodeError:
            pass

    # Paket.lock
    if stripped.startswith("STORAGE:") or stripped.startswith("RESTRICTION:") or \
       re.match(r'^(NUGET|HTTP|GIT|GITHUB)\s*$', stripped.splitlines()[0].strip(), re.IGNORECASE):
        return "paket-lock"

    # dotnet list package text output
    if "Top-level Package" in stripped or "> " in stripped:
        return "dotnet-text"

    # Pipe-delimited
    for line in stripped.splitlines()[:5]:
        if "|" in line:
            return "pipe"

    return "dotnet-text"


def parse_dotnet_json(content):
    """Parse ``dotnet list package --format json`` output.

    Args:
        content: JSON string from ``dotnet list package --format json``.

    Returns:
        List of package dicts with ``name``, ``version``, ``project`` keys.
    """
    data = json.loads(content)
    packages = []
    seen = set()

    for project in data.get("projects", []):
        for framework in project.get("frameworks", []):
            for pkg_group in ("topLevelPackages", "transitivePackages"):
                for pkg in framework.get(pkg_group, []):
                    name = pkg.get("id", "")
                    version = pkg.get("resolvedVersion", pkg.get("requestedVersion", ""))
                    key = f"{name}@{version}"
                    if key in seen or not name or not version:
                        continue
                    seen.add(key)
                    packages.append({
                        "name": name,
                        "version": version,
                        "transitive": pkg_group == "transitivePackages",
                    })

    return packages


def parse_packages_lock(content):
    """Parse ``packages.lock.json`` (NuGet lock file).

    Tracks whether each package is a ``Direct`` or ``Transitive`` dependency.

    Args:
        content: JSON string of the lock file.

    Returns:
        List of package dicts.
    """
    data = json.loads(content)
    packages = []
    seen = set()

    for framework, deps in data.get("dependencies", {}).items():
        for name, info in deps.items():
            if isinstance(info, dict):
                version = info.get("resolved", info.get("version", ""))
                pkg_type = info.get("type", "")
            else:
                version = str(info)
                pkg_type = ""

            key = f"{name}@{version}"
            if key in seen or not name or not version:
                continue
            seen.add(key)

            packages.append({
                "name": name,
                "version": version,
                "transitive": pkg_type.lower() == "transitive",
            })

    return packages


def parse_dotnet_text(content):
    """Parse ``dotnet list package`` text output.

    Matches lines like ``> PackageName  1.2.3  1.2.3``.

    Args:
        content: Raw text output.

    Returns:
        List of package dicts.
    """
    packages = []
    seen = set()

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        # Match lines starting with > (package lines)
        m = re.match(r'^>\s+(\S+)\s+(\S+)(?:\s+(\S+))?', line)
        if m:
            name = m.group(1)
            # If 3 columns: requested, resolved — use resolved
            version = m.group(3) if m.group(3) else m.group(2)
            key = f"{name}@{version}"
            if key not in seen and name and version:
                seen.add(key)
                packages.append({
                    "name": name,
                    "version": version,
                    "transitive": False,
                })

    return packages


def parse_paket_lock(content):
    """Parse a ``paket.lock`` file (Paket dependency manager for .NET).

    Args:
        content: Raw paket.lock content.

    Returns:
        List of package dicts with ``name``, ``version``, ``group`` keys.
    """
    packages = []
    seen = set()
    in_nuget = False

    for line in content.splitlines():
        if re.match(r'^NUGET\s*$', line.strip(), re.IGNORECASE):
            in_nuget = True
            continue
        if re.match(r'^(HTTP|GIT|GITHUB|GROUP)\s*$', line.strip(), re.IGNORECASE):
            in_nuget = False
            continue

        if in_nuget:
            # Package lines: "    PackageName (version)"
            m = re.match(r'^\s{4}(\S+)\s+\(([^)]+)\)', line)
            if m:
                name = m.group(1)
                version = m.group(2).strip()
                key = f"{name}@{version}"
                if key not in seen and name and version:
                    seen.add(key)
                    packages.append({
                        "name": name,
                        "version": version,
                        "transitive": False,
                    })

    return packages


def parse_pipe_format(content):
    """Parse pipe-delimited NuGet data: ``name|version``.

    Args:
        content: Raw pipe-delimited content.

    Returns:
        List of package dicts.
    """
    packages = []
    seen = set()

    for line in content.strip().splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|", 1)
        if len(parts) == 2 and parts[0].strip() and parts[1].strip():
            name = parts[0].strip()
            version = parts[1].strip()
            key = f"{name}@{version}"
            if key not in seen:
                seen.add(key)
                packages.append({
                    "name": name,
                    "version": version,
                    "transitive": False,
                })

    return packages


def build_purl(pkg):
    """Build a ``pkg:nuget/`` PURL for a NuGet package.

    Package names are lowercased per NuGet PURL convention.

    Args:
        pkg: Parsed package dict.

    Returns:
        A PURL string.
    """
    name = pkg["name"].lower()
    return f"pkg:nuget/{name}@{pkg['version']}"


def build_component(pkg):
    """Build a CycloneDX ``library`` component from parsed NuGet data.

    Args:
        pkg: Parsed package dict.

    Returns:
        A CycloneDX component dict with Trivy ``nuget`` type.
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
        {"name": "aquasecurity:trivy:PkgType", "value": "nuget"},
        {"name": "aquasecurity:trivy:SrcName", "value": pkg["name"]},
        {"name": "aquasecurity:trivy:SrcVersion", "value": pkg["version"]},
    ]
    if pkg.get("transitive"):
        properties.append({"name": "nuget:transitive", "value": "true"})

    component["properties"] = properties
    return component, purl


def generate_sbom(packages, dotnet_version=None, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM for .NET NuGet packages.

    Args:
        packages:       List of parsed package dicts.
        dotnet_version: Optional .NET version for metadata.
        serial_number:  Optional URN UUID; auto-generated if ``None``.

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    description = ".NET NuGet packages"
    if dotnet_version:
        description = f"{description} — .NET {dotnet_version}"

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
                    "name": "nuget-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "nuget-packages",
                "version": dotnet_version or "",
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
        description="Convert .NET/NuGet packages to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input: dotnet list JSON/text, packages.lock.json, paket.lock, or pipe-delimited (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--dotnet-version", default=None,
                        help=".NET SDK version (informational)")
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

    if fmt == "dotnet-json":
        packages = parse_dotnet_json(content)
    elif fmt == "packages-lock":
        packages = parse_packages_lock(content)
    elif fmt == "dotnet-text":
        packages = parse_dotnet_text(content)
    elif fmt == "paket-lock":
        packages = parse_paket_lock(content)
    else:
        packages = parse_pipe_format(content)

    sbom = generate_sbom(packages, dotnet_version=args.dotnet_version)

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
