#!/usr/bin/env python3
"""
Convert APT package listing to CycloneDX 1.5 SBOM (JSON).

Extraction command (run on target Debian/Ubuntu host):
  # Option A — native apt format (includes repo origin):
  apt list --installed 2>/dev/null | grep -v '^Listing' > apt_packages.txt

  # Option B — richer pipe-delimited format via apt-cache:
  apt list --installed 2>/dev/null | grep -v '^Listing' | awk -F/ '{print $1}' | \
    xargs dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Maintainer}|${Source}|${Homepage}|${Installed-Size}|${Section}|${Status}\n' \
    > apt_packages_rich.txt

Also grab OS identity:
  grep -E '^(ID|VERSION_ID|VERSION_CODENAME)=' /etc/os-release > os_info.txt

Input format — native apt (auto-detected):
  package/origin1,origin2 version arch [installed,automatic]
  e.g.: openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.18 amd64 [installed]

Input format — pipe-delimited (auto-detected):
  package|version|architecture|maintainer|source|homepage|installed_size|section|status

Usage:
  python3 apt_to_cyclonedx.py -i apt_packages.txt -o sbom.cdx.json --os-release os_info.txt
  python3 apt_to_cyclonedx.py -i apt_packages.txt -o sbom.cdx.json --distro debian --distro-version 12
  python3 apt_to_cyclonedx.py -i apt_packages.txt -o sbom.cdx.json --distro ubuntu --distro-version 22.04
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


DISTRO_MAP = {
    "debian": "Debian GNU/Linux",
    "ubuntu": "Ubuntu",
    "kali": "Kali GNU/Linux",
}

# Kali maps to Debian for Trivy's advisory feed
TRIVY_FAMILY_MAP = {
    "kali": "debian",
}

# Kali release → Debian base version mapping
KALI_TO_DEBIAN = {
    "2024": "12",
    "2025": "12",
    "2026": "13",
}


def parse_os_release(filepath):
    """Parse ``ID``, ``VERSION_ID``, ``VERSION_CODENAME`` from os-release.

    Args:
        filepath: Path to a local copy of ``/etc/os-release``.

    Returns:
        Dict with keys ``ID``, ``VERSION_ID``, ``VERSION_CODENAME``.
    """
    data = {}
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                key, val = line.split("=", 1)
                data[key] = val.strip('"').strip("'")
    distro = data.get("ID", "").lower()
    version = data.get("VERSION_ID", "")
    codename = data.get("VERSION_CODENAME", "")
    return distro, version, codename


def detect_format(lines):
    """Auto-detect whether input is native ``apt list`` or pipe-delimited.

    Examines the first 10 lines for the ``/`` character typical of
    apt's ``package/suite`` format.

    Args:
        lines: List of input lines.

    Returns:
        ``'apt-native'`` or ``'pipe'``.
    """
    for line in lines[:10]:
        line = line.strip()
        if not line:
            continue
        # Native apt format: "package/origin version arch [status]"
        if re.match(r"^\S+/\S+\s+\S+\s+\S+\s+\[", line):
            return "apt-native"
        # Pipe-delimited: at least 5 pipes
        if line.count("|") >= 4:
            return "pipe-delimited"
    return "apt-native"  # default


def parse_apt_native_line(line):
    """Parse a native ``apt list --installed`` line into a component dict.

    Format: package/origin1,origin2 version arch [installed,automatic]
    Example: openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.18 amd64 [installed]
    """
    line = line.strip()
    if not line:
        return None

    # Match: name/origins version arch [status]
    m = re.match(
        r"^(\S+?)/([\S]+)\s+(\S+)\s+(\S+)\s+\[([^\]]*)\]",
        line,
    )
    if not m:
        return None

    name = m.group(1)
    origins = m.group(2)        # e.g. "jammy-updates,jammy-security,now"
    version = m.group(3)
    arch = m.group(4)
    status = m.group(5)         # e.g. "installed,automatic" or "installed"

    # Clean origins — remove "now" which just means currently installed version
    origin_list = [o for o in origins.split(",") if o != "now"]
    origin_str = ",".join(origin_list) if origin_list else ""

    automatic = "automatic" in status

    # Parse epoch from version
    epoch = None
    upstream_version = version
    epoch_match = re.match(r"^(\d+):(.+)$", version)
    if epoch_match:
        epoch = epoch_match.group(1)
        upstream_version = epoch_match.group(2)

    # Try to infer source package from name (heuristic: strip -dev, -doc, -dbg, lib prefix patterns)
    # This is a best-effort; pipe-delimited format from dpkg-query is more accurate
    source_name = name
    for suffix in ("-dev", "-dbg", "-dbgsym", "-doc", "-data", "-common", "-bin", "-utils"):
        if name.endswith(suffix):
            source_name = name[: -len(suffix)]
            break

    return {
        "name": name,
        "version": version,
        "upstream_version": upstream_version,
        "epoch": epoch,
        "arch": arch,
        "origins": origin_str,
        "automatic": automatic,
        "source_name": source_name,
        "source_version": version,
        "maintainer": "",
        "homepage": "",
        "installed_size": "",
        "section": "",
    }


def parse_pipe_line(line):
    """Parse a pipe-delimited ``dpkg-query`` style line into a component dict.

    Fields: package|version|architecture|maintainer|source|homepage|installed_size|section[|status]
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

    epoch = None
    upstream_version = version
    epoch_match = re.match(r"^(\d+):(.+)$", version)
    if epoch_match:
        epoch = epoch_match.group(1)
        upstream_version = epoch_match.group(2)

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
        "version": version,
        "upstream_version": upstream_version,
        "epoch": epoch,
        "arch": arch,
        "origins": "",
        "automatic": False,
        "source_name": source_name,
        "source_version": source_version,
        "maintainer": maintainer,
        "homepage": homepage,
        "installed_size": installed_size,
        "section": section,
    }


def build_purl(pkg, trivy_family, distro_version):
    """Build a ``pkg:deb/`` Package URL for an APT/dpkg package.

    Args:
        pkg:            Dict from a parse function.
        trivy_family:   Trivy OS family name (e.g. ``debian``, ``ubuntu``).
        distro_version: Distribution version string.

    Returns:
        A PURL string.
    """
    distro_qualifier = f"{trivy_family}-{distro_version}" if distro_version else trivy_family
    purl = f"pkg:deb/{trivy_family}/{pkg['name']}@{pkg['version']}?arch={pkg['arch']}&distro={distro_qualifier}"
    return purl


def build_component(pkg, trivy_family, distro_version):
    """Build a CycloneDX ``library`` component from parsed APT data.

    Args:
        pkg:            Dict from a parse function.
        trivy_family:   Trivy OS family name.
        distro_version: Distribution version.

    Returns:
        A CycloneDX component dict with Trivy-compatible properties.
    """
    purl = build_purl(pkg, trivy_family, distro_version)
    bom_ref = hashlib.sha256(purl.encode()).hexdigest()[:16]

    component = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": purl,
    }

    if pkg["maintainer"]:
        component["publisher"] = pkg["maintainer"]
        component["supplier"] = {"name": pkg["maintainer"]}

    if pkg["homepage"] and pkg["homepage"] not in ("", "(none)"):
        component["externalReferences"] = [
            {"type": "website", "url": pkg["homepage"]}
        ]

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
    if pkg["origins"]:
        properties.append({"name": "apt:origins", "value": pkg["origins"]})
    if pkg["automatic"]:
        properties.append({"name": "apt:automatic", "value": "true"})

    # Trivy properties for OS package identification
    properties.append({"name": "aquasecurity:trivy:PkgType", "value": trivy_family})
    properties.append({"name": "aquasecurity:trivy:SrcName", "value": pkg["source_name"]})
    properties.append({"name": "aquasecurity:trivy:SrcVersion", "value": pkg["source_version"]})

    if properties:
        component["properties"] = properties

    return component, purl


def generate_sbom(packages, trivy_family, distro_version, display_distro=None, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM document for APT packages.

    Supports Kali-to-Debian version mapping via ``KALI_TO_DEBIAN``.

    Args:
        packages:       List of parsed package dicts.
        trivy_family:   Trivy OS family (``debian``, ``ubuntu``, etc.).
        distro_version: Distribution version.
        display_distro: Human-readable distro name for metadata.
        serial_number:  Optional URN UUID; auto-generated if ``None``.

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    label = display_distro or trivy_family
    description = DISTRO_MAP.get(label, label.title())
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
                    "name": "apt-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "operating-system",
                "name": trivy_family,
                "version": distro_version or "",
                "description": description,
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
        component, purl = build_component(pkg, trivy_family, distro_version)
        if purl not in seen_purls:
            seen_purls.add(purl)
            sbom["components"].append(component)

    return sbom


def main():
    parser = argparse.ArgumentParser(
        description="Convert APT/dpkg package listing to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input file: 'apt list --installed' output or pipe-delimited dpkg-query (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--distro", default=None,
                        help="OS family: debian, ubuntu, kali (auto-detected from --os-release)")
    parser.add_argument("--distro-version", default=None,
                        help="OS version: e.g. 11, 12, 22.04, 24.04")
    parser.add_argument("--os-release", default=None,
                        help="Path to os_info.txt (from /etc/os-release)")
    args = parser.parse_args()

    # Resolve distro identity
    distro = args.distro
    distro_version = args.distro_version
    display_distro = None

    if args.os_release:
        os_distro, os_version, os_codename = parse_os_release(args.os_release)
        if not distro:
            distro = os_distro
        if not distro_version:
            distro_version = os_version

    if not distro:
        print("ERROR: --distro is required (debian, ubuntu, or kali) or provide --os-release",
              file=sys.stderr)
        sys.exit(1)

    distro = distro.lower()
    display_distro = distro

    # Map Kali to Debian for Trivy matching
    trivy_family = TRIVY_FAMILY_MAP.get(distro, distro)

    if distro == "kali" and distro_version:
        # Map Kali year-based version to Debian base
        kali_year = distro_version.split(".")[0]
        mapped = KALI_TO_DEBIAN.get(kali_year)
        if mapped:
            print(f"Kali {distro_version} → mapping to Debian {mapped} for Trivy advisory matching",
                  file=sys.stderr)
            distro_version = mapped
        else:
            print(f"WARNING: Unknown Kali version '{distro_version}'. Defaulting to Debian 12.",
                  file=sys.stderr)
            distro_version = "12"

    if not distro_version:
        print("ERROR: --distro-version is required for Trivy vulnerability matching.\n"
              "  Debian: 11, 12, 13\n"
              "  Ubuntu: 20.04, 22.04, 24.04\n"
              "  Kali:   2024.4, 2025.1 (auto-mapped to Debian base)",
              file=sys.stderr)
        sys.exit(1)

    if trivy_family not in ("debian", "ubuntu"):
        print(f"WARNING: Trivy family '{trivy_family}' may not have a dedicated advisory feed.",
              file=sys.stderr)

    print(f"Distro: {display_distro} → Trivy family: {trivy_family}, version: {distro_version}",
          file=sys.stderr)

    # Read input
    if args.input == "-":
        lines = sys.stdin.read().strip().splitlines()
    else:
        with open(args.input, "r") as f:
            lines = f.read().strip().splitlines()

    # Auto-detect format
    fmt = detect_format(lines)
    print(f"Detected input format: {fmt}", file=sys.stderr)

    # Parse packages
    packages = []
    skipped = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if fmt == "apt-native":
            pkg = parse_apt_native_line(line)
        else:
            pkg = parse_pipe_line(line)
        if pkg:
            packages.append(pkg)
        else:
            skipped += 1

    # Generate SBOM
    sbom = generate_sbom(packages, trivy_family, distro_version, display_distro=display_distro)

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
