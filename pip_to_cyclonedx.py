#!/usr/bin/env python3
"""
Convert pip package listing to CycloneDX 1.5 SBOM (JSON).

Extraction commands (run on target host):

  # Option A — JSON format (recommended, includes metadata):
  pip list --format json > pip_packages.txt
  # or for a specific Python:
  python3 -m pip list --format json > pip_packages.txt

  # Option B — freeze format (version pinned):
  pip freeze > pip_packages.txt

  # Option C — verbose format (includes location, author):
  pip list --format json --verbose > pip_packages.txt
  # Note: --verbose flag requires pip 23.0+; on older pip use:
  pip list --format columns --verbose > pip_packages.txt

  # Option D — per-virtualenv:
  /path/to/venv/bin/pip list --format json > pip_packages_venv.txt

  # Option E — discover ALL virtual environments on a host:
  find / -type f -name 'activate' -path '*/bin/activate' 2>/dev/null | \
    sed 's|/bin/activate$||' > venv_paths.txt
  # Then collect from each:
  while IFS= read -r venv; do
    name=$(basename "$venv")
    "$venv/bin/pip" list --format json > "pip_packages_${name}.json" 2>/dev/null
  done < venv_paths.txt

  # Option F — discover conda environments:
  conda env list --json 2>/dev/null | python3 -c \
    "import sys,json; [print(e) for e in json.load(sys.stdin)['envs']]" > conda_envs.txt
  while IFS= read -r env; do
    name=$(basename "$env")
    "$env/bin/pip" list --format json > "pip_packages_conda_${name}.json" 2>/dev/null
  done < conda_envs.txt

  # Option G — system-wide + all user site-packages:
  pip list --format json > pip_packages_system.json
  pip list --user --format json > pip_packages_user.json

Input formats (auto-detected):
  1) JSON: [{"name": "requests", "version": "2.31.0"}, ...]
  2) Freeze: requests==2.31.0
  3) Columns: Package    Version    Location

Usage:
  # System packages:
  python3 pip_to_cyclonedx.py -i pip_packages.txt -o sbom.cdx.json

  # Tag a specific virtual environment:
  python3 pip_to_cyclonedx.py -i pip_packages_myapp.json -o sbom_myapp.cdx.json \
    --venv-name myapp --venv-path /opt/myapp/venv --python-version 3.11

  # Batch-convert all discovered venvs (one SBOM each):
  for f in pip_packages_*.json; do
    name=$(echo "$f" | sed 's/pip_packages_//;s/\\.json//')
    python3 pip_to_cyclonedx.py -i "$f" -o "sbom_pip_${name}.cdx.json" --venv-name "$name"
  done
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
    """Auto-detect the pip output format.

    Args:
        content: Raw file content.

    Returns:
        One of ``'json'``, ``'freeze'``, or ``'columns'``.
    """
    stripped = content.strip()
    if stripped.startswith("["):
        return "json"
    for line in stripped.splitlines()[:5]:
        line = line.strip()
        if "==" in line:
            return "freeze"
        if re.match(r"^Package\s+Version", line, re.IGNORECASE):
            return "columns"
    return "freeze"


def parse_json_format(content):
    """Parse ``pip list --format json`` output.

    Args:
        content: JSON string (array of ``{"name": ..., "version": ...}``).

    Returns:
        List of package dicts.
    """
    data = json.loads(content)
    packages = []
    for pkg in data:
        packages.append({
            "name": pkg.get("name", ""),
            "version": pkg.get("version", ""),
            "location": pkg.get("location", ""),
            "installer": pkg.get("installer", "pip"),
            "author": pkg.get("author", ""),
            "home_page": pkg.get("home-page", ""),
            "license": pkg.get("license", ""),
        })
    return packages


def parse_freeze_format(content):
    """Parse ``pip freeze`` output (``name==version`` lines).

    Skips editable installs (``-e``) and lines without ``==``.

    Args:
        content: Raw freeze output.

    Returns:
        List of package dicts.
    """
    packages = []
    for line in content.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle: name==version, name>=version, name @ file://...
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*(.+)$", line)
        if m:
            packages.append({
                "name": m.group(1),
                "version": m.group(2).strip(),
                "location": "",
                "installer": "pip",
                "author": "",
                "home_page": "",
                "license": "",
            })
            continue
        # editable installs: -e git+...#egg=name
        m = re.match(r"^-e\s+.+#egg=(\S+)", line)
        if m:
            packages.append({
                "name": m.group(1),
                "version": "0.0.0-editable",
                "location": "",
                "installer": "pip",
                "author": "",
                "home_page": "",
                "license": "",
            })
    return packages


def parse_columns_format(content):
    """Parse ``pip list --format columns`` tabular output.

    Skips header and separator lines.

    Args:
        content: Raw columns output.

    Returns:
        List of package dicts.
    """
    packages = []
    lines = content.strip().splitlines()
    # Skip header and separator lines
    data_start = 0
    for i, line in enumerate(lines):
        if re.match(r"^-+\s+-+", line):
            data_start = i + 1
            break
    for line in lines[data_start:]:
        parts = line.split()
        if len(parts) >= 2:
            packages.append({
                "name": parts[0],
                "version": parts[1],
                "location": parts[2] if len(parts) > 2 else "",
                "installer": "pip",
                "author": "",
                "home_page": "",
                "license": "",
            })
    return packages


def normalize_pypi_name(name):
    """Normalize a PyPI package name per `PEP 503 <https://peps.python.org/pep-0503/>`_.

    Replaces runs of ``-``, ``_``, or ``.`` with a single hyphen and
    lowercases the result.

    Args:
        name: Raw package name.

    Returns:
        Normalized lowercase name.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def build_purl(pkg, venv_name=None):
    """Build a ``pkg:pypi/`` PURL, optionally qualified with a venv name.

    Args:
        pkg:       Parsed package dict.
        venv_name: Optional virtualenv name to add as ``?venv=`` qualifier.

    Returns:
        A PURL string.
    """
    name = normalize_pypi_name(pkg["name"])
    base = f"pkg:pypi/{name}@{pkg['version']}"
    qualifiers = []
    if venv_name:
        qualifiers.append(f"venv={venv_name}")
    if qualifiers:
        return f"{base}?{'&'.join(qualifiers)}"
    return base


def build_component(pkg, venv_name=None, venv_path=None):
    """Build a CycloneDX ``library`` component from parsed pip data.

    Args:
        pkg:       Parsed package dict.
        venv_name: Optional virtualenv name for property annotation.
        venv_path: Optional virtualenv filesystem path for property annotation.

    Returns:
        A CycloneDX component dict.
    """
    purl = build_purl(pkg, venv_name=venv_name)
    bom_ref = hashlib.sha256(purl.encode()).hexdigest()[:16]

    component = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": purl,
    }

    if pkg.get("author"):
        component["publisher"] = pkg["author"]
    if pkg.get("license") and pkg["license"] not in ("", "UNKNOWN"):
        component["licenses"] = [{"license": {"name": pkg["license"]}}]
    if pkg.get("home_page") and pkg["home_page"] not in ("", "UNKNOWN"):
        component["externalReferences"] = [
            {"type": "website", "url": pkg["home_page"]}
        ]

    properties = []
    if pkg.get("location"):
        properties.append({"name": "pip:location", "value": pkg["location"]})
    if pkg.get("installer"):
        properties.append({"name": "pip:installer", "value": pkg["installer"]})
    if venv_name:
        properties.append({"name": "pip:venv", "value": venv_name})
    if venv_path:
        properties.append({"name": "pip:venv_path", "value": venv_path})

    properties.append({"name": "aquasecurity:trivy:PkgType", "value": "pip"})

    if properties:
        component["properties"] = properties

    return component, purl


def generate_sbom(packages, python_version=None, venv_name=None,
                  venv_path=None, serial_number=None):
    """Generate a complete CycloneDX 1.5 SBOM document for pip packages.

    Args:
        packages:       List of parsed package dicts.
        python_version: Optional Python version for metadata.
        venv_name:      Optional virtualenv name.
        venv_path:      Optional virtualenv filesystem path.
        serial_number:  Optional URN UUID; auto-generated if ``None``.

    Returns:
        A dict representing the full CycloneDX 1.5 SBOM.
    """
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    description = "Python packages (pip)"
    if venv_name:
        description = f"{description} — venv: {venv_name}"
    if python_version:
        description = f"{description} — Python {python_version}"

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
                    "name": "pip-to-cyclonedx",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "python-packages",
                "version": python_version or "",
                "description": description,
                "properties": [
                    {"name": "aquasecurity:trivy:Class", "value": "lang-pkgs"},
                ],
            },
        },
        "components": [],
    }

    # Add venv metadata properties if present
    if venv_name:
        sbom["metadata"]["component"]["properties"].append(
            {"name": "pip:venv", "value": venv_name}
        )
    if venv_path:
        sbom["metadata"]["component"]["properties"].append(
            {"name": "pip:venv_path", "value": venv_path}
        )

    seen_purls = set()
    for pkg in packages:
        component, purl = build_component(pkg, venv_name=venv_name,
                                          venv_path=venv_path)
        if purl not in seen_purls:
            seen_purls.add(purl)
            sbom["components"].append(component)

    return sbom


def main():
    parser = argparse.ArgumentParser(
        description="Convert pip package listing to CycloneDX SBOM (JSON)"
    )
    parser.add_argument("-i", "--input", default="-",
                        help="Input file: pip list --format json, pip freeze, or columns (default: stdin)")
    parser.add_argument("-o", "--output", default="-",
                        help="Output SBOM file (default: stdout)")
    parser.add_argument("--python-version", default=None,
                        help="Python version (e.g. 3.11) — informational only")
    parser.add_argument("--venv-name", default=None,
                        help="Virtual environment name (e.g. myapp, .venv) — tags every component")
    parser.add_argument("--venv-path", default=None,
                        help="Virtual environment path (e.g. /opt/myapp/venv) — recorded in properties")
    args = parser.parse_args()

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

    if fmt == "json":
        packages = parse_json_format(content)
    elif fmt == "freeze":
        packages = parse_freeze_format(content)
    else:
        packages = parse_columns_format(content)

    # Generate SBOM
    sbom = generate_sbom(packages, python_version=args.python_version,
                         venv_name=args.venv_name, venv_path=args.venv_path)

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
