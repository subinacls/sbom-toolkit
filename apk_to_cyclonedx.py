#!/usr/bin/env python3
"""
Convert pipe-delimited Alpine APK package listing to CycloneDX 1.5 SBOM (JSON).

Extraction command (run on target Alpine host):
  awk -F: 'BEGIN{OFS="|"}
    /^P:/{name=$2} /^V:/{ver=$2} /^A:/{arch=$2} /^o:/{origin=$2}
    /^m:/{maint=$2} /^U:/{url=$2} /^T:/{desc=$2} /^t:/{btime=$2}
    /^c:/{commit=$2}
    /^$/{print name,ver,arch,origin,maint,url,desc,btime,commit;
         name=ver=arch=origin=maint=url=desc=btime=commit=""}
  ' /lib/apk/db/installed > apk_packages.txt

Also grab OS version:
  cat /etc/alpine-release > alpine_version.txt
  # or: grep -E '^(ID|VERSION_ID)=' /etc/os-release > os_info.txt

Input format (pipe-delimited):
  name|version|arch|origin|maintainer|url|description|buildtime|commit

Usage:
  python3 apk_to_cyclonedx.py -i apk_packages.txt -o sbom.cdx.json --distro-version 3.18
  python3 apk_to_cyclonedx.py -i apk_packages.txt -o sbom.cdx.json --alpine-release alpine_version.txt
  python3 apk_to_cyclonedx.py -i apk_packages.txt -o sbom.cdx.json --os-release os_info.txt
"""

__version__ = "1.0.0"
__author__ = "SBOM Toolkit Contributors"
__license__ = "MIT"

import json
import sys
import uuid
import hashlib
import argparse
from datetime import datetime, timezone


def parse_alpine_release(filepath):
    """Read the Alpine Linux version from ``/etc/alpine-release``.

    Args:
        filepath: Path to a local copy of the release file.

    Returns:
        Version string (e.g. ``3.18.4``), or ``None``.
    """
    with open(filepath, "r") as f:
        version = f.read().strip()
    # alpine-release contains e.g. "3.18.4" — Trivy wants the major.minor like "3.18"
    parts = version.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return version


def parse_os_release(filepath):
    """Parse ``ID`` and ``VERSION_ID`` from an ``os-release`` snippet.

    Args:
        filepath: Path to a local copy of ``/etc/os-release``.

    Returns:
        Tuple of ``(distro_id, version_id)``; either may be ``None``.
    """
    distro = None
    version = None
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("ID="):
                distro = line.split("=", 1)[1].strip('"').strip("'").lower()
            elif line.startswith("VERSION_ID="):
                version = line.split("=", 1)[1].strip('"').strip("'")
    return distro, version


def epoch_to_iso(epoch_str):
    """Convert a Unix epoch string to an ISO 8601 datetime string.

    Args:
        epoch_str: String representation of a Unix timestamp.

    Returns:
        ISO 8601 formatted datetime string, or ``None`` on parse failure.
    """
    try:
        ts = int(epoch_str.strip())
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        return None


def parse_apk_line(line):
    """Parse a single pipe-delimited APK info line into a component dict.

    Fields: name|version|arch|origin|maintainer|url|description|buildtime|commit
    """
    fields = line.strip().split("|")
    if len(fields) < 9:
        return None

    name = fields[0].strip()
    version = fields[1].strip()
    arch = fields[2].strip()
    origin = fields[3].strip()          # Source/origin package name
    maintainer = fields[4].strip()
    url = fields[5].strip()
    description = fields[6].strip()
    buildtime = fields[7].strip()
    commit = fields[8].strip()

    if not name or not version:
        return None

    # Origin is the source package name; if empty, same as package name
    if not origin:
        origin = name

    return {
        "name": name,
        "version": version,
        "arch": arch,
        "origin": origin,
        "maintainer": maintainer,
        "url": url,
        "description": description,
        "buildtime": buildtime,
        "commit": commit,
    }


def build_purl(pkg, distro_version):
    """Build a ``pkg:apk/`` Package URL for an Alpine package.

    PURL spec: pkg:apk/alpine/<name>@<version>?arch=<arch>&distro=alpine-<ver>
    """
    distro_qualifier = f"alpine-{distro_version}" if distro_version else "alpine"
    purl = f"pkg:apk/alpine/{pkg['name']}@{pkg['version']}?arch={pkg['arch']}&distro={distro_qualifier}"
    return purl


def build_component(pkg, distro_version):
    """Build a CycloneDX ``library`` component from parsed APK data.

    Generates a deterministic ``bom-ref`` and attaches Alpine-specific
    and Trivy-compatible properties.

    Args:
        pkg:            Dict from :func:`parse_apk_line`.
        distro_version: Alpine version (e.g. ``3.18``).

    Returns:
        A CycloneDX component dict.
    """
    purl = build_purl(pkg, distro_version)

    # Deterministic BOM ref from PURL
    bom_ref = hashlib.sha256(purl.encode()).hexdigest()[:16]

    component = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": purl,
    }

    # Description
    if pkg["description"]:
        component["description"] = pkg["description"]

    # Publisher / supplier from maintainer
    if pkg["maintainer"]:
        component["publisher"] = pkg["maintainer"]
        component["supplier"] = {"name": pkg["maintainer"]}

    # External reference for URL
    if pkg["url"] and pkg["url"] not in ("", "(none)"):
        component["externalReferences"] = [
            {"type": "website", "url": pkg["url"]}
        ]

    # Properties for apk-specific metadata + Trivy hints
    properties = []

    if pkg["arch"]:
        properties.append({"name": "apk:arch", "value": pkg["arch"]})
    if pkg["origin"]:
        properties.append({"name": "apk:origin", "value": pkg["origin"]})
    if pkg["commit"]:
        properties.append({"name": "apk:commit", "value": pkg["commit"]})

    build_ts = epoch_to_iso(pkg["buildtime"])
    if build_ts:
        properties.append({"name": "apk:buildTime", "value": build_ts})

    # Trivy uses these aquasecurity properties for OS package identification
    properties.append({"name": "aquasecurity:trivy:PkgType", "value": "alpine"})
    properties.append({"name": "aquasecurity:trivy:SrcName", "value": pkg["origin"]})
    properties.append({"name": "aquasecurity:trivy:SrcVersion", "value": pkg["version"]})

    if properties:
        component["properties"] = properties

    return component, purl


def generate_sbom(packages, distro_version, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM document for Alpine packages.

    Args:
        packages:      List of dicts from :func:`parse_apk_line`.
        distro_version: Alpine version string.
        serial_number: Optional URN UUID; auto-generated if ``None``.

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    description = "Alpine Linux"
    if distro_version:
        description = f"{description} {distro_version}"

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
                    "name": "apk-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "operating-system",
                "name": "alpine",
                "version": distro_version or "",
                "description": description,
                "properties": [
                    {"name": "aquasecurity:trivy:Type", "value": "alpine"},
                    {"name": "aquasecurity:trivy:Class", "value": "os-pkgs"},
                ],
            },
        },
        "components": [],
    }

    seen_purls = set()
    for pkg in packages:
        component, purl = build_component(pkg, distro_version)
        if purl not in seen_purls:
            seen_purls.add(purl)
            sbom["components"].append(component)

    return sbom


def main():
    parser = argparse.ArgumentParser(
        description="Convert apk package listing to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input file from apk extraction (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--distro-version", default=None,
                        help="Alpine version: e.g. 3.18, 3.19, 3.20")
    parser.add_argument("--alpine-release", default=None,
                        help="Path to alpine_version.txt (from /etc/alpine-release)")
    parser.add_argument("--os-release", default=None,
                        help="Path to os_info.txt (from /etc/os-release)")
    args = parser.parse_args()

    # Resolve Alpine version
    distro_version = args.distro_version

    if args.alpine_release and not distro_version:
        distro_version = parse_alpine_release(args.alpine_release)

    if args.os_release and not distro_version:
        distro, version = parse_os_release(args.os_release)
        if distro and distro != "alpine":
            print(f"WARNING: os-release says '{distro}', not 'alpine'. Proceeding anyway.",
                  file=sys.stderr)
        if version:
            # VERSION_ID in Alpine is like "3.18.4" — trim to major.minor
            parts = version.split(".")
            distro_version = f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else version

    if not distro_version:
        print("ERROR: Alpine version is required. Use one of:\n"
              "  --distro-version 3.18\n"
              "  --alpine-release alpine_version.txt\n"
              "  --os-release os_info.txt",
              file=sys.stderr)
        sys.exit(1)

    print(f"Alpine version: {distro_version}", file=sys.stderr)

    # Read input
    if args.input == "-":
        lines = sys.stdin.read().strip().splitlines()
    else:
        with open(args.input, "r") as f:
            lines = f.read().strip().splitlines()

    # Parse packages
    packages = []
    skipped = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        pkg = parse_apk_line(line)
        if pkg:
            packages.append(pkg)
        else:
            skipped += 1

    # Generate SBOM
    sbom = generate_sbom(packages, distro_version)

    # Write output
    output_json = json.dumps(sbom, indent=2)
    if args.output == "-":
        print(output_json)
    else:
        with open(args.output, "w") as f:
            f.write(output_json)
            f.write("\n")
        print(f"SBOM written to {args.output} — {len(sbom['components'])} components"
              f"{f' ({skipped} skipped)' if skipped else ''}",
              file=sys.stderr)


if __name__ == "__main__":
    main()
