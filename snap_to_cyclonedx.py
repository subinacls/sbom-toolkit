#!/usr/bin/env python3
"""
Convert Snap package listing to CycloneDX 1.5 SBOM (JSON).

Extraction commands (run on target host):

  # Option A — snap list (recommended):
  snap list > snap_packages.txt

  # Option B — JSON via snapd REST API:
  curl -s --unix-socket /run/snapd.socket http://localhost/v2/snaps > snap_packages.txt

  # Option C — pipe-delimited (manual):
  snap list | tail -n +2 | awk '{print $1"|"$2"|"$4"|"$5"|"$6}' > snap_packages.txt
  # Fields: name|version|publisher|tracking|notes

Input formats (auto-detected):
  1) snap list text output (columns: Name Version Rev Tracking Publisher Notes)
  2) snapd REST API JSON (/v2/snaps)
  3) Pipe-delimited: name|version  or  name|version|publisher|tracking|notes

Usage:
  python3 snap_to_cyclonedx.py -i snap_packages.txt -o sbom.cdx.json
  snap list | python3 snap_to_cyclonedx.py -o sbom.cdx.json
  python3 snap_to_cyclonedx.py -i snap_packages.txt -o sbom.cdx.json --distro ubuntu --distro-version 22.04
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
    """Auto-detect the snap listing format.

    Distinguishes between ``snap list`` text, snapd REST API JSON, and
    pipe-delimited input.

    Args:
        content: Raw file content as a string.

    Returns:
        One of ``'snap-list'``, ``'snapd-json'``, or ``'pipe'``.
    """
    stripped = content.strip()

    # JSON from snapd API
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            if "result" in data and isinstance(data["result"], list):
                return "snapd-json"
        except json.JSONDecodeError:
            pass

    # JSON array
    if stripped.startswith("["):
        try:
            json.loads(stripped)
            return "snapd-json-array"
        except json.JSONDecodeError:
            pass

    # snap list text output — first line is header
    first_line = stripped.splitlines()[0].strip() if stripped.splitlines() else ""
    if re.match(r'^Name\s+Version\s+Rev', first_line, re.IGNORECASE):
        return "snap-list"

    # Pipe-delimited
    for line in stripped.splitlines()[:5]:
        if "|" in line:
            return "pipe"

    # Default to snap list (might be missing header)
    return "snap-list"


def parse_snap_list(content):
    """Parse ``snap list`` columnar text output.

    Expected columns: ``Name  Version  Rev  Tracking  Publisher  Notes``.

    Args:
        content: Raw ``snap list`` output.

    Returns:
        List of package dicts with keys ``name``, ``version``, ``revision``,
        ``tracking``, ``publisher``, ``notes``.
    """
    packages = []
    lines = content.strip().splitlines()

    # Find header line and determine column positions
    header_idx = -1
    for i, line in enumerate(lines):
        if re.match(r'^Name\s+Version\s+Rev', line, re.IGNORECASE):
            header_idx = i
            break

    if header_idx == -1:
        # No header found, try plain whitespace-split
        start = 0
    else:
        start = header_idx + 1

    for line in lines[start:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue

        name = parts[0]
        version = parts[1]
        rev = parts[2] if len(parts) > 2 else ""
        tracking = parts[3] if len(parts) > 3 else ""
        publisher = parts[4] if len(parts) > 4 else ""
        notes = parts[5] if len(parts) > 5 else ""

        # Skip if this looks like a header line that slipped through
        if name.lower() == "name" and version.lower() == "version":
            continue

        packages.append({
            "name": name,
            "version": version,
            "revision": rev,
            "tracking": tracking,
            "publisher": publisher,
            "notes": notes,
            "confinement": "",
            "type": "",
        })

    return packages


def parse_snapd_json(content):
    """Parse snapd REST API JSON output (``/v2/snaps``).

    Args:
        content: JSON string from the snapd API.

    Returns:
        List of package dicts.
    """
    data = json.loads(content)

    # Handle /v2/snaps response wrapper
    if isinstance(data, dict) and "result" in data:
        snap_list = data["result"]
    elif isinstance(data, list):
        snap_list = data
    else:
        snap_list = []

    packages = []
    seen = set()

    for snap in snap_list:
        name = snap.get("name", "")
        version = snap.get("version", "")
        key = f"{name}@{version}"
        if key in seen or not name or not version:
            continue
        seen.add(key)

        packages.append({
            "name": name,
            "version": version,
            "revision": str(snap.get("revision", "")),
            "tracking": snap.get("tracking-channel", snap.get("channel", "")),
            "publisher": snap.get("publisher", {}).get("display-name", "")
                         if isinstance(snap.get("publisher"), dict)
                         else str(snap.get("publisher", "")),
            "notes": "",
            "confinement": snap.get("confinement", ""),
            "type": snap.get("type", ""),
        })

    return packages


def parse_pipe_format(content):
    """Parse pipe-delimited snap data: ``name|version[|publisher|tracking|notes]``.

    Args:
        content: Raw pipe-delimited content.

    Returns:
        List of package dicts.
    """
    packages = []
    seen = set()

    for line in content.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 2:
            continue

        name = parts[0].strip()
        version = parts[1].strip()
        if not name or not version:
            continue

        key = f"{name}@{version}"
        if key in seen:
            continue
        seen.add(key)

        packages.append({
            "name": name,
            "version": version,
            "revision": "",
            "tracking": parts[3].strip() if len(parts) > 3 else "",
            "publisher": parts[2].strip() if len(parts) > 2 else "",
            "notes": parts[4].strip() if len(parts) > 4 else "",
            "confinement": "",
            "type": "",
        })

    return packages


def build_purl(pkg, distro=None):
    """Build a ``pkg:snap/`` PURL for a snap package.

    Note:
        Snap does not have an official PURL type in the specification.
        The ``snap`` type is used as a de-facto convention.

    Args:
        pkg:    Parsed package dict.
        distro: Optional distro qualifier for the PURL.

    Returns:
        A PURL string.
    """
    name = pkg["name"]
    version = pkg["version"]
    qualifiers = []
    if distro:
        qualifiers.append(f"distro={distro}")
    if pkg.get("tracking"):
        qualifiers.append(f"channel={pkg['tracking']}")
    qual_str = "&".join(qualifiers)
    if qual_str:
        return f"pkg:snap/{name}@{version}?{qual_str}"
    return f"pkg:snap/{name}@{version}"


def build_component(pkg, distro=None):
    """Build a CycloneDX ``library`` component from parsed snap data.

    Args:
        pkg:    Parsed package dict.
        distro: Optional distro identifier.

    Returns:
        A CycloneDX component dict.
    """
    purl = build_purl(pkg, distro)
    bom_ref = hashlib.sha256(purl.encode()).hexdigest()[:16]

    component = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": purl,
    }

    if pkg.get("publisher"):
        component["publisher"] = pkg["publisher"]

    properties = [
        {"name": "aquasecurity:trivy:PkgType", "value": "snap"},
    ]

    if pkg.get("revision"):
        properties.append({"name": "snap:revision", "value": pkg["revision"]})
    if pkg.get("tracking"):
        properties.append({"name": "snap:channel", "value": pkg["tracking"]})
    if pkg.get("confinement"):
        properties.append({"name": "snap:confinement", "value": pkg["confinement"]})
    if pkg.get("type"):
        properties.append({"name": "snap:type", "value": pkg["type"]})
    if pkg.get("notes") and pkg["notes"] != "-":
        properties.append({"name": "snap:notes", "value": pkg["notes"]})

    component["properties"] = properties
    return component, purl


def generate_sbom(packages, distro=None, distro_version=None, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM document for snap packages.

    Args:
        packages:       List of parsed package dicts.
        distro:         Distribution ID for metadata.
        distro_version: Distribution version for metadata.
        serial_number:  Optional URN UUID; auto-generated if ``None``.

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    description = "Snap packages"
    if distro and distro_version:
        description = f"{description} — {distro} {distro_version}"

    meta_name = distro or "linux"
    meta_version = distro_version or ""

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
                    "name": "snap-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": meta_name,
                "version": meta_version,
                "description": description,
                "properties": [
                    {"name": "aquasecurity:trivy:Class", "value": "os-pkgs"},
                ],
            },
        },
        "components": [],
    }

    seen_purls = set()
    for pkg in packages:
        component, purl = build_component(pkg, distro)
        if purl not in seen_purls:
            seen_purls.add(purl)
            sbom["components"].append(component)

    return sbom


def main():
    parser = argparse.ArgumentParser(
        description="Convert snap package listing to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input file: snap list output, snapd API JSON, or pipe-delimited (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--distro", default=None,
                        help="Distro name (e.g. ubuntu, fedora) — informational")
    parser.add_argument("--distro-version", default=None,
                        help="Distro version (e.g. 22.04)")
    parser.add_argument("--os-release", default=None,
                        help="Path to /etc/os-release to auto-detect distro and version")
    args = parser.parse_args()

    # Auto-detect from os-release if provided
    distro = args.distro
    distro_version = args.distro_version

    if args.os_release:
        try:
            with open(args.os_release, "r") as f:
                os_rel = f.read()
            for line in os_rel.splitlines():
                line = line.strip()
                if line.startswith("ID="):
                    val = line.split("=", 1)[1].strip().strip('"').lower()
                    if not distro:
                        distro = val
                elif line.startswith("VERSION_ID="):
                    val = line.split("=", 1)[1].strip().strip('"')
                    if not distro_version:
                        distro_version = val
        except (IOError, OSError) as e:
            print(f"WARNING: Could not read {args.os_release}: {e}", file=sys.stderr)

    # Read input
    if args.input == "-":
        content = sys.stdin.read()
    else:
        with open(args.input, "r") as f:
            content = f.read()

    content = content.strip()
    if not content:
        print("ERROR: Empty input", file=sys.stderr)
        sys.exit(1)

    # Auto-detect and parse
    fmt = detect_format(content)
    print(f"Detected input format: {fmt}", file=sys.stderr)

    if fmt == "snapd-json" or fmt == "snapd-json-array":
        packages = parse_snapd_json(content)
    elif fmt == "snap-list":
        packages = parse_snap_list(content)
    else:
        packages = parse_pipe_format(content)

    # Generate SBOM
    sbom = generate_sbom(packages, distro=distro, distro_version=distro_version)

    # Write output
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
