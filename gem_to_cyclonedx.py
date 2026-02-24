#!/usr/bin/env python3
"""
Convert Ruby gem listing to CycloneDX 1.5 SBOM (JSON).

Extraction commands (run on target host):

  # Option A — JSON format (recommended):
  gem list --local --no-details 2>/dev/null | \
    ruby -e 'STDIN.each_line{|l| m=l.match(/^(\\S+)\\s+\\((.+)\\)/); next unless m; m[2].split(", ").each{|v| puts "#{m[1]}|#{v}"}}' \
    > gem_packages.txt

  # Option B — simple list:
  gem list --local > gem_packages.txt

  # Option C — Gemfile.lock (from a project):
  cp Gemfile.lock gem_packages.txt

  # Option D — bundler JSON:
  bundle list --paths > gem_packages.txt

Input formats (auto-detected):
  1) Pipe-delimited: name|version
  2) gem list native: name (version1, version2)
  3) Gemfile.lock: standard Gemfile.lock format

Usage:
  python3 gem_to_cyclonedx.py -i gem_packages.txt -o sbom.cdx.json
  python3 gem_to_cyclonedx.py -i Gemfile.lock -o sbom.cdx.json
  python3 gem_to_cyclonedx.py -i gem_packages.txt -o sbom.cdx.json --ruby-version 3.2
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
    """Auto-detect the Ruby gem listing format.

    Args:
        content: Raw file content.

    Returns:
        One of ``'gemfile-lock'``, ``'gem-list'``, or ``'pipe'``.
    """
    stripped = content.strip()
    lines = stripped.splitlines()
    for line in lines[:10]:
        line = line.strip()
        if "|" in line:
            return "pipe"
        if line == "GEM" or line == "PLATFORMS" or line == "DEPENDENCIES" or line == "BUNDLED WITH":
            return "gemfile-lock"
        if re.match(r"^\S+\s+\(.+\)$", line):
            return "gem-list"
    # Check if it looks like a Gemfile.lock
    if "GEM\n" in stripped or "\n  specs:\n" in stripped:
        return "gemfile-lock"
    return "gem-list"


def parse_pipe_format(content):
    """Parse pipe-delimited gem data: ``name|version``.

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


def parse_gem_list_format(content):
    """Parse ``gem list`` output: ``name (version1, version2)``.

    Uses only the first (latest) version when multiple are listed.

    Args:
        content: Raw ``gem list`` output.

    Returns:
        List of package dicts.
    """
    packages = []
    for line in content.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^(\S+)\s+\((.+)\)$", line)
        if m:
            name = m.group(1)
            versions = [v.strip().rstrip(" default") for v in m.group(2).split(",")]
            for version in versions:
                version = version.strip()
                if version:
                    packages.append({"name": name, "version": version})
    return packages


def parse_gemfile_lock(content):
    """Parse ``Gemfile.lock`` (Bundler lock file).

    Extracts gems from the ``GEM > specs:`` section.

    Args:
        content: Raw Gemfile.lock content.

    Returns:
        List of package dicts.
    """
    packages = []
    in_specs = False
    for line in content.splitlines():
        # Start of specs section
        if line.strip() == "specs:":
            in_specs = True
            continue
        # End of GEM section
        if in_specs and not line.startswith("    ") and not line.startswith("\t"):
            if line.strip() in ("", "PLATFORMS", "DEPENDENCIES", "RUBY VERSION", "BUNDLED WITH"):
                in_specs = False
                continue
        if in_specs:
            # Gem entries are indented 4 spaces: "    name (version)"
            m = re.match(r"^\s{4}(\S+)\s+\(([^)]+)\)$", line)
            if m:
                packages.append({
                    "name": m.group(1),
                    "version": m.group(2),
                })
    return packages


def build_purl(pkg):
    """Build a ``pkg:gem/`` PURL for a RubyGem.

    Args:
        pkg: Parsed package dict with ``name`` and ``version``.

    Returns:
        A PURL string.
    """
    return f"pkg:gem/{pkg['name']}@{pkg['version']}"


def build_component(pkg):
    """Build a CycloneDX ``library`` component from parsed gem data.

    Args:
        pkg: Parsed package dict.

    Returns:
        A CycloneDX component dict with Trivy ``gemspec`` type.
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
        {"name": "aquasecurity:trivy:PkgType", "value": "gemspec"},
    ]
    component["properties"] = properties

    return component, purl


def generate_sbom(packages, ruby_version=None, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM document for Ruby gems.

    Args:
        packages:     List of parsed gem dicts.
        ruby_version: Optional Ruby version for metadata.
        serial_number: Optional URN UUID; auto-generated if ``None``.

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    description = "Ruby gems"
    if ruby_version:
        description = f"{description} — Ruby {ruby_version}"

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
                    "name": "gem-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "ruby-gems",
                "version": ruby_version or "",
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
        description="Convert Ruby gem listing to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input: gem list output, pipe-delimited, or Gemfile.lock (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--ruby-version", default=None,
                        help="Ruby version (informational)")
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

    if fmt == "pipe":
        packages = parse_pipe_format(content)
    elif fmt == "gemfile-lock":
        packages = parse_gemfile_lock(content)
    else:
        packages = parse_gem_list_format(content)

    sbom = generate_sbom(packages, ruby_version=args.ruby_version)

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
