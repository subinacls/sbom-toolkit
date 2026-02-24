#!/usr/bin/env python3
"""
Convert pipe-delimited dpkg package listing to CycloneDX 1.5 SBOM (JSON).

Reads 8-field pipe-delimited output produced by::

    dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Maintainer}|\
    ${Source}|${Homepage}|${Installed-Size}|${Section}\\n'

Requires ``--distro`` and ``--distro-version`` to construct correct PURLs
and Trivy-compatible metadata.  Emits ``pkg:deb/`` PURLs.

Extraction command (run on target Debian/Ubuntu host):
  dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Maintainer}|${Source}|${Homepage}|${Installed-Size}|${Section}\n' > dpkg_packages.txt

Also grab OS identity:
  cat /etc/os-release | grep -E '^(ID|VERSION_ID)=' > os_info.txt

Input format (pipe-delimited):
  package|version|architecture|maintainer|source|homepage|installed_size|section

Usage:
  python3 dpkg_to_cyclonedx.py -i dpkg_packages.txt -o sbom.cdx.json --distro debian --distro-version 11
  python3 dpkg_to_cyclonedx.py -i dpkg_packages.txt -o sbom.cdx.json --distro ubuntu --distro-version 22.04
  python3 dpkg_to_cyclonedx.py -i dpkg_packages.txt -o sbom.cdx.json --os-release os_info.txt
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


# Trivy-recognized OS family names and their human-readable descriptions
DISTRO_MAP = {
    "debian": "Debian GNU/Linux",
    "ubuntu": "Ubuntu",
    "kali": "Kali GNU/Linux",
}

# Distros that Trivy does not recognise natively — map to a supported family
TRIVY_FAMILY_MAP = {
    "kali": "debian",
}

# Kali rolling release → Debian base-version mapping
KALI_TO_DEBIAN = {
    "2024": "12",
    "2025": "12",
    "2026": "13",
}


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


def parse_dpkg_line(line):
    """Parse a single pipe-delimited ``dpkg-query`` line into a dict.

    Args:
        line: Pipe-delimited string with 8 fields.

    Returns:
        Dict with keys ``name``, ``version``, ``arch``, ``maintainer``,
        ``source``, ``homepage``, ``installed_size``, ``section``,
        ``epoch``, ``upstream_version``, or ``None`` for malformed lines.
    """
    fields = line.strip().split("|")
    if len(fields) < 8:
        return None

    name = fields[0].strip()
    version = fields[1].strip()
    arch = fields[2].strip()
    maintainer = fields[3].strip()
    source = fields[4].strip()
    homepage = fields[5].strip()
    installed_size = fields[6].strip()
    section = fields[7].strip()

    if not name or not version:
        return None

    # Parse epoch from version string.  dpkg versions: [epoch:]upstream_version[-debian_revision]
    epoch = None
    upstream_version = version
    epoch_match = re.match(r"^(\d+):(.+)$", version)
    if epoch_match:
        epoch = epoch_match.group(1)
        upstream_version = epoch_match.group(2)

    # Source package: dpkg may emit "source (source_version)" or just "source" or empty
    # If empty, source package name == binary package name
    source_name = name
    source_version = version
    if source:
        src_match = re.match(r"^(\S+?)(?:\s+\(([^)]+)\))?$", source)
        if src_match:
            source_name = src_match.group(1)
            if src_match.group(2):
                source_version = src_match.group(2)

    return {
        "name": name,
        "version": version,              # Full version as dpkg reports it
        "upstream_version": upstream_version,  # Version without epoch
        "epoch": epoch,
        "arch": arch,
        "maintainer": maintainer,
        "source_name": source_name,
        "source_version": source_version,
        "homepage": homepage,
        "installed_size": installed_size,  # KB
        "section": section,
    }


def build_purl(pkg, distro, distro_version):
    """Build a Package URL (PURL) for a Debian/Ubuntu package.

    Automatically maps non-Trivy distros (e.g. ``kali``) to their Trivy
    family (``debian``) via :data:`TRIVY_FAMILY_MAP` and
    :data:`KALI_TO_DEBIAN`.

    Args:
        pkg:             Dict from :func:`parse_dpkg_line`.
        distro:          Distribution ID (e.g. ``debian``, ``ubuntu``, ``kali``).
        distro_version:  Distribution version (e.g. ``12``, ``22.04``).

    Returns:
        A ``pkg:deb/`` PURL string.
    """
    # Map unsupported Trivy families (kali → debian)
    trivy_family = TRIVY_FAMILY_MAP.get(distro, distro)
    trivy_version = distro_version
    if distro in KALI_TO_DEBIAN:
        trivy_version = KALI_TO_DEBIAN.get(distro_version, distro_version)

    distro_qualifier = f"{trivy_family}-{trivy_version}" if trivy_version else trivy_family

    purl_version = pkg["version"]
    purl = f"pkg:deb/{trivy_family}/{pkg['name']}@{purl_version}?arch={pkg['arch']}&distro={distro_qualifier}"
    return purl


def build_component(pkg, distro, distro_version):
    """Build a CycloneDX ``library`` component from parsed dpkg data.

    Attaches Debian-specific properties and Trivy ``aquasecurity:trivy:*``
    metadata for vulnerability matching.

    Args:
        pkg:             Dict from :func:`parse_dpkg_line`.
        distro:          Distribution ID.
        distro_version:  Distribution version.

    Returns:
        A CycloneDX component dict.
    """
    purl = build_purl(pkg, distro, distro_version)

    # Deterministic BOM ref from PURL
    bom_ref = hashlib.sha256(purl.encode()).hexdigest()[:16]

    component = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": purl,
    }

    # Publisher / supplier from maintainer
    if pkg["maintainer"]:
        component["publisher"] = pkg["maintainer"]
        component["supplier"] = {"name": pkg["maintainer"]}

    # External reference for homepage
    if pkg["homepage"] and pkg["homepage"] not in ("", "(none)"):
        component["externalReferences"] = [
            {"type": "website", "url": pkg["homepage"]}
        ]

    # Properties for dpkg-specific metadata + Trivy hints
    properties = []

    if pkg["epoch"]:
        properties.append({"name": "deb:epoch", "value": pkg["epoch"]})
    if pkg["arch"]:
        properties.append({"name": "deb:arch", "value": pkg["arch"]})
    if pkg["source_name"]:
        properties.append({"name": "deb:source", "value": pkg["source_name"]})
    if pkg["source_version"] and pkg["source_version"] != pkg["version"]:
        properties.append({"name": "deb:sourceVersion", "value": pkg["source_version"]})
    if pkg["section"]:
        properties.append({"name": "deb:section", "value": pkg["section"]})
    if pkg["installed_size"]:
        properties.append({"name": "deb:installedSize", "value": f"{pkg['installed_size']}KB"})

    # Trivy uses these aquasecurity properties for OS package identification
    trivy_family = TRIVY_FAMILY_MAP.get(distro, distro)
    properties.append({"name": "aquasecurity:trivy:PkgType", "value": trivy_family})
    properties.append({"name": "aquasecurity:trivy:SrcName", "value": pkg["source_name"]})
    properties.append({"name": "aquasecurity:trivy:SrcVersion", "value": pkg["source_version"]})

    if properties:
        component["properties"] = properties

    return component, purl


def generate_sbom(packages, distro, distro_version, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM document for dpkg packages.

    Args:
        packages:       List of dicts from :func:`parse_dpkg_line`.
        distro:         Distribution ID (``debian``, ``ubuntu``, etc.).
        distro_version: Distribution version.
        serial_number:  Optional URN UUID; auto-generated if ``None``.

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    display_name = DISTRO_MAP.get(distro, distro.title())
    if distro_version:
        display_name = f"{display_name} {distro_version}"

    # Map to Trivy-recognised family (kali → debian)
    trivy_family = TRIVY_FAMILY_MAP.get(distro, distro)
    trivy_version = distro_version
    if distro in KALI_TO_DEBIAN:
        trivy_version = KALI_TO_DEBIAN.get(distro_version, distro_version)

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
                    "name": "dpkg-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "operating-system",
                "name": trivy_family,
                "version": trivy_version or "",
                "description": display_name,
                "properties": [
                    {"name": "aquasecurity:trivy:Type", "value": trivy_family},
                    {"name": "aquasecurity:trivy:Class", "value": "os-pkgs"},
                ],
            },
        },
        "components": [],
    }

    seen_purls = set()
    for pkg in packages:
        component, purl = build_component(pkg, distro, distro_version)
        if purl not in seen_purls:
            seen_purls.add(purl)
            sbom["components"].append(component)

    return sbom


def main():
    parser = argparse.ArgumentParser(
        description="Convert dpkg-query output to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input file from dpkg-query (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--distro", default=None,
                        help="OS family: debian, ubuntu (auto-detected from --os-release if provided)")
    parser.add_argument("--distro-version", default=None,
                        help="OS version: e.g. 11, 12, 22.04, 24.04")
    parser.add_argument("--os-release", default=None,
                        help="Path to os_info.txt (extracted from /etc/os-release)")
    args = parser.parse_args()

    # Resolve distro identity
    distro = args.distro
    distro_version = args.distro_version

    if args.os_release:
        os_distro, os_version = parse_os_release(args.os_release)
        if not distro:
            distro = os_distro
        if not distro_version:
            distro_version = os_version

    if not distro:
        print("ERROR: --distro is required (debian, ubuntu, or kali) or provide --os-release file",
              file=sys.stderr)
        sys.exit(1)

    # Warn when the distro requires mapping to a Trivy-recognised family
    trivy_family = TRIVY_FAMILY_MAP.get(distro, distro)
    if trivy_family != distro:
        mapped_ver = KALI_TO_DEBIAN.get(distro_version, distro_version) if distro in KALI_TO_DEBIAN else distro_version
        print(f"NOTE: '{distro}' mapped to Trivy family '{trivy_family}' (version {mapped_ver})",
              file=sys.stderr)

    if not distro_version:
        print("WARNING: --distro-version not set; Trivy matching may be less accurate",
              file=sys.stderr)

    distro = distro.lower()
    if distro not in DISTRO_MAP:
        print(f"WARNING: '{distro}' is not a recognized distribution. "
              f"Expected one of: {', '.join(DISTRO_MAP.keys())}. "
              f"Trivy matching may not work.",
              file=sys.stderr)

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
        pkg = parse_dpkg_line(line)
        if pkg:
            packages.append(pkg)
        else:
            skipped += 1

    # Generate SBOM
    sbom = generate_sbom(packages, distro, distro_version)

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
