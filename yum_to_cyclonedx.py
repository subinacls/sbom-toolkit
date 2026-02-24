#!/usr/bin/env python3
"""
Convert YUM/DNF/RPM package listing to CycloneDX 1.5 SBOM (JSON).

Extraction command (run on target CentOS/RHEL/Fedora/Rocky/Alma/Oracle/Amazon host):

  # Option A — use rpm directly (richest metadata, same as rpm_to_cyclonedx.py):
  rpm -qa --queryformat '%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}|%{VENDOR}|%{PACKAGER}|%{SOURCERPM}|%{SIGPGP:pgpsig}|%{BUILDTIME}|%{INSTALLTIME}\n' > yum_packages.txt

  # Option B — native yum/dnf format:
  yum list installed 2>/dev/null | tail -n +2 > yum_packages.txt
  # or on newer systems:
  dnf list installed 2>/dev/null | tail -n +2 > yum_packages.txt

  # Option C — repoquery for repo origin info:
  repoquery -a --installed --qf '%{name}|%{epoch}|%{version}|%{release}|%{arch}|%{vendor}|%{from_repo}|%{sourcerpm}' > yum_packages.txt
  # or dnf:
  dnf repoquery --installed --qf '%{name}|%{epoch}|%{version}|%{release}|%{arch}|%{vendor}|%{from_repo}|%{sourcerpm}' > yum_packages.txt

Also grab OS identity:
  grep -E '^(ID|VERSION_ID)=' /etc/os-release > os_info.txt

Input formats (auto-detected):
  1) rpm pipe-delimited (11 fields): name|epoch|version|release|arch|vendor|packager|source_rpm|signature|buildtime|installtime
  2) repoquery pipe-delimited (8 fields): name|epoch|version|release|arch|vendor|from_repo|source_rpm
  3) yum/dnf native: name.arch  version-release  @repo

Usage:
  python3 yum_to_cyclonedx.py -i yum_packages.txt -o sbom.cdx.json --os-release os_info.txt
  python3 yum_to_cyclonedx.py -i yum_packages.txt -o sbom.cdx.json --distro centos --distro-version 7
  python3 yum_to_cyclonedx.py -i yum_packages.txt -o sbom.cdx.json --distro rhel --distro-version 8
  python3 yum_to_cyclonedx.py -i yum_packages.txt -o sbom.cdx.json --distro fedora --distro-version 39
  python3 yum_to_cyclonedx.py -i yum_packages.txt -o sbom.cdx.json --distro amzn --distro-version 2
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


# User-facing distro names
DISTRO_DISPLAY = {
    "rhel": "Red Hat Enterprise Linux",
    "centos": "CentOS",
    "fedora": "Fedora",
    "rocky": "Rocky Linux",
    "alma": "AlmaLinux",
    "ol": "Oracle Linux",
    "amzn": "Amazon Linux",
    "redhat": "Red Hat Enterprise Linux",
}

# Map OS IDs from /etc/os-release to Trivy family names
# Trivy recognizes: redhat, centos, fedora, rocky, alma, oracle, amazon
TRIVY_FAMILY_MAP = {
    "rhel": "redhat",
    "centos": "centos",
    "fedora": "fedora",
    "rocky": "rocky",
    "almalinux": "alma",
    "alma": "alma",
    "ol": "oracle",
    "oracle": "oracle",
    "amzn": "amazon",
    "amazon": "amazon",
    "redhat": "redhat",
    "scientific": "redhat",     # Scientific Linux → RHEL advisories
}


def parse_os_release(filepath):
    """Parse ``ID`` and ``VERSION_ID`` from an ``os-release`` snippet.

    Args:
        filepath: Path to a local copy of ``/etc/os-release``.

    Returns:
        Dict with keys ``ID``, ``VERSION_ID``.
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
    # For RHEL/CentOS, trim to major version (e.g. "7.9" → "7")
    if distro in ("rhel", "centos", "ol", "scientific", "rocky", "almalinux") and "." in version:
        version = version.split(".")[0]
    return distro, version


def epoch_to_iso(epoch_str):
    """Convert a Unix epoch string to an ISO 8601 datetime string.

    Args:
        epoch_str: String representation of a Unix timestamp.

    Returns:
        ISO 8601 formatted datetime, or ``None`` on failure.
    """
    try:
        ts = int(epoch_str.strip())
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        return None


def detect_format(lines):
    """Auto-detect input format from the first non-empty lines.

    Distinguishes between 11-field ``rpm -qa``, 8-field ``repoquery``,
    and native ``yum/dnf list installed`` output.

    Args:
        lines: List of input lines.

    Returns:
        One of ``'rpm-full'``, ``'repoquery'``, or ``'yum-native'``.
    """
    for line in lines[:20]:
        line = line.strip()
        if not line:
            continue
        pipe_count = line.count("|")
        # rpm 11-field format
        if pipe_count >= 10:
            return "rpm-full"
        # repoquery 8-field format
        if pipe_count >= 7:
            return "repoquery"
        # Any pipe-delimited
        if pipe_count >= 4:
            return "pipe-generic"
        # yum/dnf native: "name.arch   version-release   @repo"
        if re.match(r"^\S+\.\S+\s+\S+\s+@\S+", line):
            return "yum-native"
        # yum/dnf with "Installed Packages" header or continuation lines
        if line in ("Installed Packages",):
            continue
    return "yum-native"


def parse_rpm_full_line(line):
    """Parse an ``rpm -qa`` 11-field pipe-delimited line into a dict.

    Fields: name|epoch|version|release|arch|vendor|packager|source_rpm|signature|buildtime|installtime
    """
    fields = line.strip().split("|")
    if len(fields) < 11:
        return None

    name = fields[0].strip()
    epoch = fields[1].strip() if fields[1].strip() and fields[1].strip() not in ("0", "(none)") else None
    version = fields[2].strip()
    release = fields[3].strip()
    arch = fields[4].strip()
    vendor = fields[5].strip()
    packager = fields[6].strip()
    source_rpm = fields[7].strip()
    signature = fields[8].strip()
    buildtime = fields[9].strip()
    installtime = fields[10].strip()

    if not name or not version:
        return None

    return {
        "name": name,
        "epoch": epoch,
        "version": version,
        "release": release,
        "arch": arch,
        "vendor": vendor,
        "packager": packager,
        "source_rpm": source_rpm,
        "signature": signature,
        "buildtime": buildtime,
        "installtime": installtime,
        "from_repo": "",
    }


def parse_repoquery_line(line):
    """Parse a ``repoquery`` 8-field pipe-delimited line into a dict.

    Fields: name|epoch|version|release|arch|vendor|from_repo|source_rpm
    """
    fields = line.strip().split("|")
    if len(fields) < 8:
        return None

    name = fields[0].strip()
    epoch = fields[1].strip() if fields[1].strip() and fields[1].strip() not in ("0", "(none)") else None
    version = fields[2].strip()
    release = fields[3].strip()
    arch = fields[4].strip()
    vendor = fields[5].strip()
    from_repo = fields[6].strip()
    source_rpm = fields[7].strip()

    if not name or not version:
        return None

    return {
        "name": name,
        "epoch": epoch,
        "version": version,
        "release": release,
        "arch": arch,
        "vendor": vendor,
        "packager": "",
        "source_rpm": source_rpm,
        "signature": "",
        "buildtime": "",
        "installtime": "",
        "from_repo": from_repo,
    }


def parse_yum_native_line(line):
    """Parse a ``yum``/``dnf`` native 'list installed' line into a dict.

    Format: name.arch   epoch:version-release   @repo
    Examples:
      openssl.x86_64  1:1.0.2k-25.el7_9  @updates
      bash.x86_64     4.2.46-35.el7_9     @base
    """
    line = line.strip()
    if not line or line == "Installed Packages":
        return None

    # Split on whitespace
    parts = line.split()
    if len(parts) < 3:
        return None

    name_arch = parts[0]
    ver_rel = parts[1]
    repo = parts[2].lstrip("@") if parts[2].startswith("@") else parts[2]

    # Split name.arch
    if "." not in name_arch:
        return None
    # Last dot separates name from arch (package names can contain dots)
    last_dot = name_arch.rfind(".")
    name = name_arch[:last_dot]
    arch = name_arch[last_dot + 1:]

    # Parse epoch:version-release
    epoch = None
    epoch_match = re.match(r"^(\d+):(.+)$", ver_rel)
    if epoch_match:
        epoch = epoch_match.group(1)
        if epoch == "0":
            epoch = None
        ver_rel = epoch_match.group(2)

    # Split version-release
    if "-" in ver_rel:
        last_dash = ver_rel.rfind("-")
        version = ver_rel[:last_dash]
        release = ver_rel[last_dash + 1:]
    else:
        version = ver_rel
        release = ""

    if not name or not version:
        return None

    return {
        "name": name,
        "epoch": epoch,
        "version": version,
        "release": release,
        "arch": arch,
        "vendor": "",
        "packager": "",
        "source_rpm": "",
        "signature": "",
        "buildtime": "",
        "installtime": "",
        "from_repo": repo,
    }


def infer_source_name(pkg):
    """Infer the source package name from ``source_rpm`` or the package name.

    Args:
        pkg: Parsed package dict.

    Returns:
        The source package name string.
    """
    if pkg["source_rpm"] and pkg["source_rpm"] != "(none)":
        # source_rpm looks like "openssl-1.0.2k-25.el7_9.src.rpm"
        # Strip version-release.src.rpm to get source name
        srpm = pkg["source_rpm"]
        m = re.match(r"^(.+)-[^-]+-[^-]+\.src\.rpm$", srpm)
        if m:
            return m.group(1)
    return pkg["name"]


def build_full_version(pkg):
    """Build the full version string in the format Trivy expects.

    Combines epoch, version, and release into ``[epoch:]version[-release]``.

    Args:
        pkg: Parsed package dict.

    Returns:
        Formatted version string.
    """
    version = pkg["version"]
    if pkg["release"]:
        version = f"{version}-{pkg['release']}"
    if pkg["epoch"]:
        version = f"{pkg['epoch']}:{version}"
    return version


def build_purl(pkg, trivy_family, distro_version):
    """Build a ``pkg:rpm/`` Package URL for an RPM-based package.

    Args:
        pkg:            Parsed package dict.
        trivy_family:   Trivy OS family (``redhat``, ``centos``, etc.).
        distro_version: Distribution version.

    Returns:
        A PURL string.
    """
    distro_qualifier = f"{trivy_family}-{distro_version}" if distro_version else trivy_family

    purl_version = f"{pkg['version']}-{pkg['release']}" if pkg["release"] else pkg["version"]
    if pkg["epoch"]:
        purl_version = f"{pkg['epoch']}:{purl_version}"

    purl = f"pkg:rpm/{trivy_family}/{pkg['name']}@{purl_version}?arch={pkg['arch']}&distro={distro_qualifier}"
    return purl


def build_component(pkg, trivy_family, distro_version):
    """Build a CycloneDX ``library`` component from parsed YUM/RPM data.

    Args:
        pkg:            Parsed package dict.
        trivy_family:   Trivy OS family.
        distro_version: Distribution version.

    Returns:
        A CycloneDX component dict with RPM and Trivy properties.
    """
    purl = build_purl(pkg, trivy_family, distro_version)
    bom_ref = hashlib.sha256(purl.encode()).hexdigest()[:16]
    full_version = build_full_version(pkg)
    source_name = infer_source_name(pkg)

    component = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": pkg["name"],
        "version": full_version,
        "purl": purl,
    }

    if pkg["vendor"] and pkg["vendor"] not in ("", "(none)"):
        component["publisher"] = pkg["vendor"]
        component["supplier"] = {"name": pkg["vendor"]}

    # Properties
    properties = []

    if pkg["epoch"]:
        properties.append({"name": "rpm:epoch", "value": pkg["epoch"]})
    if pkg["release"]:
        properties.append({"name": "rpm:release", "value": pkg["release"]})
    if pkg["arch"]:
        properties.append({"name": "rpm:arch", "value": pkg["arch"]})
    if pkg["source_rpm"] and pkg["source_rpm"] != "(none)":
        properties.append({"name": "rpm:sourceRpm", "value": pkg["source_rpm"]})
    if pkg["signature"] and pkg["signature"] not in ("", "(none)"):
        properties.append({"name": "rpm:signature", "value": pkg["signature"]})
    if pkg["from_repo"]:
        properties.append({"name": "yum:fromRepo", "value": pkg["from_repo"]})

    build_ts = epoch_to_iso(pkg["buildtime"]) if pkg["buildtime"] else None
    if build_ts:
        properties.append({"name": "rpm:buildTime", "value": build_ts})

    install_ts = pkg["installtime"].strip() if pkg["installtime"] else None
    if install_ts:
        properties.append({"name": "rpm:installTime", "value": install_ts})

    # Trivy properties for OS package identification
    properties.append({"name": "aquasecurity:trivy:PkgType", "value": trivy_family})
    properties.append({"name": "aquasecurity:trivy:SrcName", "value": source_name})
    properties.append({"name": "aquasecurity:trivy:SrcVersion", "value": full_version})

    if properties:
        component["properties"] = properties

    return component, purl


def generate_sbom(packages, trivy_family, distro_version, display_distro=None, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM document for YUM/DNF packages.

    Supports all RPM-based distros via ``TRIVY_FAMILY_MAP``.

    Args:
        packages:       List of parsed package dicts.
        trivy_family:   Trivy OS family.
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
    description = DISTRO_DISPLAY.get(label, label.title())
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
                    "name": "yum-to-cyclonedx",
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
        description="Convert YUM/DNF package listing to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input file: yum/dnf list, repoquery, or rpm -qa output (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--distro", default=None,
                        help="OS family: rhel, centos, fedora, rocky, alma, ol, amzn")
    parser.add_argument("--distro-version", default=None,
                        help="OS major version: e.g. 7, 8, 9, 39, 2")
    parser.add_argument("--os-release", default=None,
                        help="Path to os_info.txt (from /etc/os-release)")
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
        print("ERROR: --distro is required or provide --os-release.\n"
              "  Supported: rhel, centos, fedora, rocky, alma, ol, amzn",
              file=sys.stderr)
        sys.exit(1)

    distro = distro.lower()
    display_distro = distro

    # Map to Trivy family name
    trivy_family = TRIVY_FAMILY_MAP.get(distro)
    if not trivy_family:
        print(f"WARNING: '{distro}' not in known distro map. Using '{distro}' as Trivy family.",
              file=sys.stderr)
        trivy_family = distro

    if not distro_version:
        print("ERROR: --distro-version is required for Trivy vulnerability matching.\n"
              "  RHEL/CentOS: 7, 8, 9\n"
              "  Fedora: 38, 39, 40\n"
              "  Rocky/Alma: 8, 9\n"
              "  Oracle Linux: 7, 8, 9\n"
              "  Amazon Linux: 2, 2023",
              file=sys.stderr)
        sys.exit(1)

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
        if not line or line == "Installed Packages":
            continue

        pkg = None
        if fmt == "rpm-full":
            pkg = parse_rpm_full_line(line)
        elif fmt == "repoquery":
            pkg = parse_repoquery_line(line)
        elif fmt in ("pipe-generic", "repoquery"):
            pkg = parse_repoquery_line(line)
        else:
            pkg = parse_yum_native_line(line)

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
