#!/usr/bin/env python3
"""
Convert Java/Maven/Gradle dependencies to CycloneDX 1.5 SBOM (JSON).

Extraction commands:

  # Option A — Maven dependency tree (recommended):
  mvn dependency:list -DoutputFile=maven_packages.txt -DincludeScope=runtime
  # or
  mvn dependency:list -DoutputAbsoluteArtifactFileName=false -DoutputFile=maven_packages.txt

  # Option B — Gradle dependencies:
  gradle dependencies --configuration runtimeClasspath 2>/dev/null | \
    grep -E '^\\s*[+\\\\|]' | sed 's/.*--- //' | sed 's/ (.*)$//' | \
    grep ':' | sort -u > maven_packages.txt

  # Option C — List JARs from a lib directory:
  ls -1 /path/to/lib/*.jar | xargs -I{} basename {} .jar | \
    sed 's/\\\\(.*\\\\)-\\\\([0-9].*\\\\)/\\\\1|\\\\2/' > maven_packages.txt

  # Option D — pipe-delimited (manual):
  echo "groupId:artifactId|version" > maven_packages.txt

Input formats (auto-detected):
  1) Maven dependency:list output (groupId:artifactId:type:version:scope)
  2) Gradle-style (groupId:artifactId:version)
  3) Pipe-delimited: groupId:artifactId|version  OR  artifactId|version

Usage:
  python3 maven_to_cyclonedx.py -i maven_packages.txt -o sbom.cdx.json
  mvn dependency:list | python3 maven_to_cyclonedx.py -o sbom.cdx.json
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
    """Auto-detect the Maven/Gradle listing format.

    Distinguishes ``mvn dependency:list``, Gradle dependency tree,
    and pipe-delimited input.

    Args:
        content: Raw file content.

    Returns:
        One of ``'maven-list'``, ``'gradle-deps'``, or ``'pipe'``.
    """
    lines = [l.strip() for l in content.strip().splitlines() if l.strip()]
    maven_count = 0
    gradle_count = 0
    pipe_count = 0

    for line in lines[:30]:
        # Clean tree prefixes
        clean = re.sub(r'^[\s|+\\`\-]+', '', line).strip()
        if not clean:
            continue

        # Maven dependency:list format: groupId:artifactId:type:version:scope
        if re.match(r'^[a-zA-Z0-9._\-]+:[a-zA-Z0-9._\-]+:[a-zA-Z]+:[0-9]', clean):
            maven_count += 1
        # Gradle style: groupId:artifactId:version
        elif re.match(r'^[a-zA-Z0-9._\-]+:[a-zA-Z0-9._\-]+:[0-9]', clean):
            gradle_count += 1
        elif "|" in clean:
            pipe_count += 1

    if maven_count >= gradle_count and maven_count >= pipe_count and maven_count > 0:
        return "maven"
    if gradle_count >= pipe_count and gradle_count > 0:
        return "gradle"
    if pipe_count > 0:
        return "pipe"
    # Default: try maven parsing
    return "maven"


def parse_maven_list(content):
    """Parse ``mvn dependency:list`` output.

    Supports both 5-field (``groupId:artifactId:type:version:scope``)
    and 6-field (with classifier) formats.

    Args:
        content: Raw Maven output.

    Returns:
        List of package dicts with ``group_id``, ``artifact_id``,
        ``version``, ``scope``, ``type``, ``classifier`` keys.

    Format: ``groupId:artifactId:type:version:scope``
    """
    packages = []
    seen = set()

    for line in content.splitlines():
        # Strip tree prefixes and whitespace
        clean = re.sub(r'^[\s|+\\`\-]+', '', line).strip()
        if not clean:
            continue
        # Skip header/info lines
        if clean.startswith(("The following", "[INFO]", "[WARNING]", "[ERROR]", "---")):
            continue

        parts = clean.split(":")
        if len(parts) == 5:
            # groupId:artifactId:type:version:scope
            group_id, artifact_id, pkg_type, version, scope = parts
        elif len(parts) == 6:
            # groupId:artifactId:type:classifier:version:scope
            group_id, artifact_id, pkg_type, classifier, version, scope = parts
        else:
            continue

        group_id = group_id.strip()
        artifact_id = artifact_id.strip()
        version = version.strip()
        scope = scope.strip() if len(parts) >= 5 else ""
        pkg_type = pkg_type.strip() if len(parts) >= 4 else "jar"

        key = f"{group_id}:{artifact_id}@{version}"
        if key in seen or not artifact_id or not version:
            continue
        seen.add(key)

        packages.append({
            "group_id": group_id,
            "artifact_id": artifact_id,
            "version": version,
            "type": pkg_type,
            "scope": scope,
        })

    return packages


def parse_gradle_deps(content):
    """Parse Gradle dependency tree output.

    Strips tree-drawing characters (``+--- \\--- |``) and version
    conflict markers (``->``).

    Args:
        content: Raw Gradle output.

    Returns:
        List of package dicts.

    Format: ``groupId:artifactId:version``
    """
    packages = []
    seen = set()

    for line in content.splitlines():
        # Strip tree prefixes
        clean = re.sub(r'^[\s|+\\`\-]+', '', line).strip()
        if not clean:
            continue
        # Remove Gradle annotations like (*), (c), -> X.Y.Z
        clean = re.sub(r'\s*\(.*?\)\s*$', '', clean).strip()
        clean = re.sub(r'\s*->\s+\S+\s*$', '', clean).strip()

        parts = clean.split(":")
        if len(parts) == 3:
            group_id, artifact_id, version = parts
        elif len(parts) == 4:
            # groupId:artifactId:classifier:version
            group_id, artifact_id, _, version = parts
        else:
            continue

        group_id = group_id.strip()
        artifact_id = artifact_id.strip()
        version = version.strip()

        # Validate they look like real coordinates
        if not re.match(r'^[a-zA-Z0-9._\-]+$', group_id):
            continue
        if not re.match(r'^[a-zA-Z0-9._\-]+$', artifact_id):
            continue

        key = f"{group_id}:{artifact_id}@{version}"
        if key in seen or not version:
            continue
        seen.add(key)

        packages.append({
            "group_id": group_id,
            "artifact_id": artifact_id,
            "version": version,
            "type": "jar",
            "scope": "",
        })

    return packages


def parse_pipe_format(content):
    """Parse pipe-delimited Maven data.

    Accepts ``groupId:artifactId|version`` or ``artifactId|version``.

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
        if len(parts) != 2:
            continue

        name_part = parts[0].strip()
        version = parts[1].strip()
        if not name_part or not version:
            continue

        if ":" in name_part:
            ga = name_part.split(":", 1)
            group_id = ga[0].strip()
            artifact_id = ga[1].strip()
        else:
            group_id = ""
            artifact_id = name_part

        key = f"{group_id}:{artifact_id}@{version}"
        if key in seen:
            continue
        seen.add(key)

        packages.append({
            "group_id": group_id,
            "artifact_id": artifact_id,
            "version": version,
            "type": "jar",
            "scope": "",
        })

    return packages


def build_purl(pkg):
    """Build a ``pkg:maven/`` PURL for a Maven/Gradle package.

    Args:
        pkg: Parsed package dict.

    Returns:
        A PURL string with ``groupId/artifactId@version``.
    """
    group = pkg["group_id"]
    artifact = pkg["artifact_id"]
    version = pkg["version"]
    if group:
        return f"pkg:maven/{group}/{artifact}@{version}"
    return f"pkg:maven/{artifact}@{version}"


def build_component(pkg):
    """Build a CycloneDX ``library`` component from parsed Maven data.

    Args:
        pkg: Parsed package dict.

    Returns:
        A CycloneDX component dict with Trivy ``jar`` type.
    """
    purl = build_purl(pkg)
    bom_ref = hashlib.sha256(purl.encode()).hexdigest()[:16]

    # Display name
    if pkg["group_id"]:
        display_name = f"{pkg['group_id']}:{pkg['artifact_id']}"
    else:
        display_name = pkg["artifact_id"]

    component = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": pkg["artifact_id"],
        "version": pkg["version"],
        "purl": purl,
    }

    if pkg["group_id"]:
        component["group"] = pkg["group_id"]

    properties = [
        {"name": "aquasecurity:trivy:PkgType", "value": "jar"},
    ]
    if pkg.get("scope"):
        properties.append({"name": "maven:scope", "value": pkg["scope"]})
    if pkg.get("type") and pkg["type"] != "jar":
        properties.append({"name": "maven:type", "value": pkg["type"]})
    if pkg.get("group_id"):
        properties.append({"name": "aquasecurity:trivy:SrcName",
                           "value": f"{pkg['group_id']}:{pkg['artifact_id']}"})
        properties.append({"name": "aquasecurity:trivy:SrcVersion",
                           "value": pkg["version"]})

    component["properties"] = properties
    return component, purl


def generate_sbom(packages, java_version=None, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM for Java Maven/Gradle packages.

    Args:
        packages:     List of parsed package dicts.
        java_version: Optional Java version for metadata.
        serial_number: Optional URN UUID; auto-generated if ``None``.

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    description = "Java/Maven dependencies"
    if java_version:
        description = f"{description} — Java {java_version}"

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
                    "name": "maven-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "java-dependencies",
                "version": java_version or "",
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
        description="Convert Maven/Gradle dependencies to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input: mvn dependency:list, gradle deps, or pipe-delimited (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--java-version", default=None,
                        help="Java version (informational)")
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

    if fmt == "maven":
        packages = parse_maven_list(content)
    elif fmt == "gradle":
        packages = parse_gradle_deps(content)
    else:
        packages = parse_pipe_format(content)

    sbom = generate_sbom(packages, java_version=args.java_version)

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
