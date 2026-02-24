#!/usr/bin/env python3
"""
Convert pipe-delimited RPM package listing to CycloneDX 1.5 SBOM (JSON).

Reads 11-field pipe-delimited output produced by::

    rpm -qa --queryformat '%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}|\
    %{VENDOR}|%{PACKAGER}|%{SOURCERPM}|%{SIGPGP:pgpsig}|%{BUILDTIME}|\
    %{INSTALLTIME}\\n'

and emits a CycloneDX 1.5 JSON SBOM with ``pkg:rpm/`` PURLs and Trivy-
compatible ``aquasecurity:trivy:*`` properties.  Hardcoded for RHEL 7
(metadata name ``redhat``, distro qualifier ``redhat-7``).

Usage::

    python3 rpm_to_cyclonedx.py < rpm_packages.txt > sbom.cdx.json
    python3 rpm_to_cyclonedx.py -i rpm_packages.txt -o sbom.cdx.json
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


def parse_rpm_line(line):
    """Parse a single pipe-delimited RPM line into a component dict.

    Args:
        line: A pipe-delimited string with 11 fields.

    Returns:
        A dict with keys ``name``, ``epoch``, ``version``, ``release``,
        ``full_version``, ``arch``, ``vendor``, ``packager``, ``source_rpm``,
        ``signature``, ``buildtime``, ``installtime``, ``purl``, or
        ``None`` if the line has fewer than 11 fields.
    """
    fields = line.strip().split("|")
    if len(fields) < 11:
        return None

    name = fields[0]
    epoch = fields[1] if fields[1] and fields[1] != "0" else None
    version = fields[2]
    release = fields[3]
    arch = fields[4]
    vendor = fields[5]
    packager = fields[6]
    source_rpm = fields[7]
    signature = fields[8]
    buildtime = fields[9]
    installtime = fields[10]

    # Build full version string
    full_version = f"{version}-{release}" if release else version
    if epoch:
        full_version = f"{epoch}:{full_version}"

    # Build PURL (Package URL) per spec: pkg:rpm/<namespace>/<name>@<version>?arch=<arch>&distro=rhel-7
    # Trivy uses the PURL distro qualifier to identify the OS for vulnerability matching
    purl_namespace = "redhat" if "Red Hat" in vendor else vendor.lower().replace(" ", "-").replace(",", "")
    if purl_namespace == "(none)":
        purl_namespace = "unknown"
    purl_version = f"{version}-{release}"
    if epoch and epoch != "0":
        purl = f"pkg:rpm/{purl_namespace}/{name}@{epoch}:{purl_version}?arch={arch}&distro=redhat-7"
    else:
        purl = f"pkg:rpm/{purl_namespace}/{name}@{purl_version}?arch={arch}&distro=redhat-7"

    return {
        "name": name,
        "epoch": epoch,
        "version": version,
        "release": release,
        "full_version": full_version,
        "arch": arch,
        "vendor": vendor,
        "packager": packager,
        "source_rpm": source_rpm,
        "signature": signature,
        "buildtime": buildtime,
        "installtime": installtime,
        "purl": purl,
    }


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


def build_component(pkg):
    """Build a CycloneDX ``library`` component from parsed RPM data.

    Generates a deterministic ``bom-ref`` from a SHA-256 hash of the PURL
    and attaches RPM-specific and Trivy-specific properties.

    Args:
        pkg: Dict returned by :func:`parse_rpm_line`.

    Returns:
        A CycloneDX component dict ready for inclusion in the SBOM.
    """
    # Deterministic BOM ref from purl
    bom_ref = hashlib.sha256(pkg["purl"].encode()).hexdigest()[:16]

    component = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": pkg["name"],
        "version": pkg["full_version"],
        "purl": pkg["purl"],
    }

    # Publisher / supplier
    if pkg["vendor"] and pkg["vendor"] != "(none)":
        component["publisher"] = pkg["vendor"]
        component["supplier"] = {"name": pkg["vendor"]}

    # Properties for RPM-specific metadata
    properties = []
    if pkg["epoch"]:
        properties.append({"name": "rpm:epoch", "value": pkg["epoch"]})
    if pkg["release"]:
        properties.append({"name": "rpm:release", "value": pkg["release"]})
    if pkg["arch"]:
        properties.append({"name": "rpm:arch", "value": pkg["arch"]})
    if pkg["source_rpm"]:
        properties.append({"name": "rpm:sourceRpm", "value": pkg["source_rpm"]})
    if pkg["signature"] and pkg["signature"] != "(none)":
        properties.append({"name": "rpm:signature", "value": pkg["signature"]})

    # Trivy uses these aquasecurity properties for OS package identification
    properties.append({"name": "aquasecurity:trivy:PkgType", "value": "redhat"})
    properties.append({"name": "aquasecurity:trivy:SrcName", "value": pkg["source_rpm"].split("-")[0] if pkg["source_rpm"] else pkg["name"]})

    build_ts = epoch_to_iso(pkg["buildtime"])
    if build_ts:
        properties.append({"name": "rpm:buildTime", "value": build_ts})

    install_ts = pkg["installtime"].strip() if pkg["installtime"] else None
    if install_ts:
        properties.append({"name": "rpm:installTime", "value": install_ts})

    if properties:
        component["properties"] = properties

    return component


def generate_sbom(packages, serial_number=None, hostname=None):
    """Generate a complete CycloneDX 1.5 SBOM document.

    De-duplicates components by PURL and sets metadata identifying the
    OS as ``redhat`` version ``7`` with Trivy ``os-pkgs`` class.

    Args:
        packages:      List of dicts from :func:`parse_rpm_line`.
        serial_number: Optional URN UUID; auto-generated if ``None``.
        hostname:      Optional hostname (currently unused, reserved).

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

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
                    "name": "rpm-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "operating-system",
                "name": "redhat",
                "version": "7",
                "description": "Red Hat Enterprise Linux Server 7",
                "properties": [
                    {"name": "aquasecurity:trivy:Type", "value": "redhat"},
                    {"name": "aquasecurity:trivy:Class", "value": "os-pkgs"},
                ],
            },
        },
        "components": [],
    }

    seen_purls = set()
    for pkg in packages:
        if pkg["purl"] not in seen_purls:
            seen_purls.add(pkg["purl"])
            sbom["components"].append(build_component(pkg))

    return sbom


def main():
    parser = argparse.ArgumentParser(
        description="Convert pipe-delimited RPM package data to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input file (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output file (default: stdout)")
    parser.add_argument("--hostname", default=None,
                        help="Hostname for the target system")
    args = parser.parse_args()

    # Read input
    if args.input == "-":
        lines = sys.stdin.read().strip().splitlines()
    else:
        with open(args.input, "r") as f:
            lines = f.read().strip().splitlines()

    # Parse packages
    packages = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        pkg = parse_rpm_line(line)
        if pkg:
            packages.append(pkg)

    # Generate SBOM
    sbom = generate_sbom(packages, hostname=args.hostname)

    # Write output
    output_json = json.dumps(sbom, indent=2)
    if args.output == "-":
        print(output_json)
    else:
        with open(args.output, "w") as f:
            f.write(output_json)
            f.write("\n")
        print(f"SBOM written to {args.output} — {len(packages)} components", file=sys.stderr)


if __name__ == "__main__":
    main()
