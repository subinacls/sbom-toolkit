# SBOM Toolkit — Autonomous CycloneDX SBOM Generation & Vulnerability Scanning

A pure-Python toolkit that connects to remote Linux hosts via SSH, discovers
every installed package manager (OS-level and language-level), extracts
package listings, converts them into
[CycloneDX 1.5](https://cyclonedx.org/) JSON SBOMs, and optionally scans
each SBOM with [Trivy](https://trivy.dev/) for known vulnerabilities.

**Zero external Python dependencies.** Runs on Python 3.6+ using only the
standard library.

---

## Features

| Capability | Details |
|---|---|
| **14 converter scripts** | RPM, dpkg, APT, APK, YUM/DNF, Snap, pip, gem, npm, Go, Cargo, Composer, Maven/Gradle, NuGet |
| **Autonomous orchestrator** | One command discovers, extracts, converts, and scans an entire remote host |
| **SSH jump-host / bastion** | Native `ProxyJump` support — single-hop or multi-hop chains |
| **Flexible auth** | SSH key, interactive password prompt (`--ask-pass`), inline password (`sshpass`), agent / `~/.ssh/config`, or auto-prompt on failure |
| **Sudo discovery** | `--sudo` flag for privileged venv/package discovery across all users |
| **Virtualenv discovery** | venv, pyenv, pipx, Poetry, conda environments |
| **Lockfile discovery** | `Cargo.lock`, `composer.lock`, `package-lock.json`, `yarn.lock`, `go.sum`, `packages.lock.json`, `pom.xml` |
| **Trivy integration** | Automatic vulnerability scanning with optional SOCKS/HTTP proxy for air-gapped DB downloads |
| **CycloneDX 1.5** | Full spec compliance with Trivy-compatible `aquasecurity:trivy:*` properties |
| **Deterministic BOM refs** | SHA-256 of PURL for stable, reproducible component identifiers |

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/wcoppola/sbom-toolkit.git
cd sbom-toolkit

# Basic scan with SSH key
python3 sbom_orchestrator.py --host 10.20.0.5 --user root --key ~/.ssh/id_rsa

# Secure interactive password prompt (never in shell history)
python3 sbom_orchestrator.py --host 10.20.0.5 --user admin --ask-pass

# Password auth — inline (requires sshpass, visible in history)
python3 sbom_orchestrator.py --host 10.20.0.5 --user admin --password 'S3cret!'

# Via jump host with sudo for full discovery
python3 sbom_orchestrator.py --host 10.30.0.100 --user deploy \
    -J bastion@10.20.0.1 --sudo

# SOCKS proxy for Trivy DB downloads (air-gapped)
python3 sbom_orchestrator.py --host 10.20.0.5 --user root \
    --trivy-proxy socks5://127.0.0.1:1080

# Generate SBOMs only (skip vulnerability scanning)
python3 sbom_orchestrator.py --host 10.20.0.5 --user root --skip-trivy
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      sbom_orchestrator.py                           │
│                                                                     │
│  ┌───────────┐   ┌──────────────┐   ┌───────────────┐   ┌───────┐ │
│  │  SSH/SCP   │──▶│  Detect OS & │──▶│  Extract Raw  │──▶│Convert│ │
│  │ RemoteHost │   │  Pkg Managers│   │  Pkg Listings │   │ SBOM  │ │
│  └───────────┘   └──────────────┘   └───────────────┘   └───┬───┘ │
│       │                                                      │     │
│       │  ProxyJump ──────────── Jump Host / Bastion          ▼     │
│       │                                              ┌─────────┐   │
│       │                                              │  Trivy  │   │
│       │                                              │  Scan   │   │
│       │                                              └────┬────┘   │
│       ▼                                                   ▼        │
│  sbom_<host>_<timestamp>/                                          │
│  ├── raw/        ← Package listings from remote                    │
│  ├── sbom/       ← CycloneDX 1.5 JSON SBOMs                      │
│  ├── reports/    ← Trivy vulnerability reports (JSON)              │
│  └── summary.json                                                  │
└─────────────────────────────────────────────────────────────────────┘
         │
         │  Delegates conversion to:
         ▼
 ┌──────────────────────────────────────────────────────────┐
 │  rpm_to_cyclonedx.py      dpkg_to_cyclonedx.py          │
 │  apk_to_cyclonedx.py      apt_to_cyclonedx.py           │
 │  yum_to_cyclonedx.py      snap_to_cyclonedx.py          │
 │  pip_to_cyclonedx.py      gem_to_cyclonedx.py           │
 │  npm_to_cyclonedx.py      go_to_cyclonedx.py            │
 │  cargo_to_cyclonedx.py    composer_to_cyclonedx.py       │
 │  maven_to_cyclonedx.py    nuget_to_cyclonedx.py          │
 └──────────────────────────────────────────────────────────┘
```

---

## Orchestrator CLI Reference

```
usage: sbom_orchestrator.py [-h] --host HOST --user USER
                            [--password PASSWORD] [--ask-pass] [--key KEY]
                            [--port PORT]
                            [-J JUMP] [--jump-key JUMP_KEY]
                            [--jump-password JUMP_PASSWORD]
                            [--outdir OUTDIR] [--trivy-proxy TRIVY_PROXY]
                            [--skip-trivy] [--skip-lang]
                            [--skip-lockfiles] [--sudo]
```

| Flag | Description |
|---|---|
| `--host` | Target hostname or IP (**required**) |
| `--user` | SSH username (**required**) |
| `--password` | SSH password (uses `sshpass`) — visible in process list/history |
| `--ask-pass` | Prompt for SSH password interactively (secure — never in history) |
| `--key` | Path to SSH private key |
| `--port` | SSH port (default: 22) |
| `-J`, `--jump` | Jump-host spec: `user@host[:port]` (supports multi-hop with `,`) |
| `--jump-key` | Separate SSH key for the jump host |
| `--jump-password` | Password for the jump host |
| `--outdir` | Output directory (default: `sbom_<host>_<timestamp>`) |
| `--trivy-proxy` | Proxy URL for Trivy DB downloads (e.g. `socks5://127.0.0.1:1080`) |
| `--skip-trivy` | Skip Trivy vulnerability scanning |
| `--skip-lang` | Skip language-level package extraction |
| `--skip-lockfiles` | Skip lockfile discovery and extraction |
| `--sudo` | Use `sudo` for privileged directory traversal |

### Authentication Priority

1. **`--ask-pass`** → Securely prompts for password via `getpass` (never in history/process list).
2. **`--password`** → Uses `sshpass -p <password>` (requires `sshpass`; visible in process list).
3. **`--key`** → Uses `ssh -i <key>`.
4. **Neither** → Falls back to `ssh-agent` or `~/.ssh/config` (`BatchMode=yes`).
5. **Auto-prompt** → If key/agent auth fails and no password was given, prompts interactively before aborting.

---

## Converter Scripts

Each converter can be used independently as a standalone CLI tool:

```bash
python3 <converter>.py -i <input_file> -o <output.cdx.json> [options]
```

### OS Package Managers

| Script | Package Manager | Input Formats | PURL Type |
|---|---|---|---|
| `rpm_to_cyclonedx.py` | RPM (RHEL 7) | 11-field pipe-delimited | `pkg:rpm/` |
| `dpkg_to_cyclonedx.py` | dpkg (Debian/Ubuntu) | 8-field pipe-delimited | `pkg:deb/` |
| `apt_to_cyclonedx.py` | APT (Debian/Ubuntu/Kali) | `apt list` native, pipe-delimited | `pkg:deb/` |
| `apk_to_cyclonedx.py` | APK (Alpine) | 9-field pipe-delimited | `pkg:apk/` |
| `yum_to_cyclonedx.py` | YUM/DNF (RHEL, CentOS, Fedora, Rocky, Alma, Oracle, Amazon) | `rpm -qa`, `repoquery`, `yum list` | `pkg:rpm/` |
| `snap_to_cyclonedx.py` | Snap | `snap list`, snapd JSON, pipe-delimited | `pkg:snap/` |

### Language Package Managers

| Script | Language | Input Formats | PURL Type |
|---|---|---|---|
| `pip_to_cyclonedx.py` | Python (pip) | JSON, freeze, columns | `pkg:pypi/` |
| `gem_to_cyclonedx.py` | Ruby (gem) | `gem list`, `Gemfile.lock`, pipe | `pkg:gem/` |
| `npm_to_cyclonedx.py` | Node.js (npm/yarn) | npm JSON, `package-lock.json`, `yarn.lock`, pipe | `pkg:npm/` |
| `go_to_cyclonedx.py` | Go | `go.sum`, `go list`, `go version -m`, pipe | `pkg:golang/` |
| `cargo_to_cyclonedx.py` | Rust (Cargo) | `Cargo.lock`, `cargo metadata`, pipe | `pkg:cargo/` |
| `composer_to_cyclonedx.py` | PHP (Composer) | `composer.lock`, `composer show`, pipe | `pkg:composer/` |
| `maven_to_cyclonedx.py` | Java (Maven/Gradle) | `mvn dependency:list`, Gradle deps, pipe | `pkg:maven/` |
| `nuget_to_cyclonedx.py` | .NET (NuGet) | `dotnet list` JSON/text, `packages.lock.json`, `paket.lock`, pipe | `pkg:nuget/` |

### Common Converter Options

```bash
python3 yum_to_cyclonedx.py -i packages.txt -o sbom.cdx.json \
    --distro centos --distro-version 8

python3 pip_to_cyclonedx.py -i packages.json -o sbom.cdx.json \
    --venv-name myapp --venv-path /opt/myapp/venv

python3 apt_to_cyclonedx.py -i apt_packages.txt -o sbom.cdx.json \
    --distro kali --distro-version 2024 --os-release os-release.txt
```

---

## Output Structure

```
sbom_10.20.0.5_20250624_143022/
├── raw/
│   ├── rpm_packages.txt           # Raw RPM listing
│   ├── pip_system_packages.json   # System pip packages
│   ├── pip_venv_opt_myapp.json    # Virtualenv packages
│   └── npm_global_packages.json   # Global npm packages
├── sbom/
│   ├── rpm.cdx.json               # CycloneDX SBOM (RPM)
│   ├── pip_system.cdx.json        # CycloneDX SBOM (pip)
│   ├── pip_venv_opt_myapp.cdx.json
│   └── npm_global.cdx.json
├── reports/
│   ├── rpm.trivy.json             # Trivy vulnerability report
│   ├── pip_system.trivy.json
│   └── npm_global.trivy.json
└── summary.json                   # Aggregated results
```

### summary.json

```json
{
  "host": "10.20.0.5",
  "timestamp": "2025-06-24T14:30:22Z",
  "os": "Red Hat Enterprise Linux Server 7",
  "total_components": 847,
  "total_vulnerabilities": 142,
  "sources": [
    {
      "label": "rpm",
      "sbom": "sbom/rpm.cdx.json",
      "components": 612,
      "report": "reports/rpm.trivy.json",
      "vulns": 128
    }
  ]
}
```

---

## Trivy Integration

### Vulnerability Scanning

Trivy scans each generated SBOM in `sbom` subcommand mode:

```bash
trivy sbom --skip-db-update --quiet --format json -o report.json sbom.cdx.json
```

### Air-Gapped / Proxy Environments

For environments without direct internet access, use a SOCKS proxy for
Trivy's vulnerability database downloads:

```bash
# Set up a SOCKS tunnel
ssh -C -D 1080 -N -f ubuntu@10.20.0.1

# Pass it to the orchestrator
python3 sbom_orchestrator.py --host 10.20.0.5 --user root \
    --trivy-proxy socks5://127.0.0.1:1080
```

The `--trivy-proxy` flag sets `ALL_PROXY` and `HTTPS_PROXY` **only** for
the Trivy subprocess — it does not affect SSH connections.

### Important Notes

- Trivy `--offline-scan` only works with `image` and `fs` subcommands, **not**
  `sbom`. Use `--skip-db-update` instead (default behavior).
- For RHEL systems, the SBOM metadata component name **must** be `"redhat"`
  (not `"rhel-server"`) for Trivy to match vulnerabilities correctly.

---

## Supported Distributions

### OS-Level (via TRIVY_FAMILY_MAP)

| Distribution | Trivy Family | Converter |
|---|---|---|
| RHEL / CentOS | `redhat` / `centos` | `yum_to_cyclonedx.py` |
| Fedora | `fedora` | `yum_to_cyclonedx.py` |
| Rocky Linux | `rocky` | `yum_to_cyclonedx.py` |
| AlmaLinux | `alma` | `yum_to_cyclonedx.py` |
| Oracle Linux | `oracle` | `yum_to_cyclonedx.py` |
| Amazon Linux | `amazon` | `yum_to_cyclonedx.py` |
| Debian | `debian` | `dpkg_to_cyclonedx.py` / `apt_to_cyclonedx.py` |
| Ubuntu | `ubuntu` | `dpkg_to_cyclonedx.py` / `apt_to_cyclonedx.py` |
| Kali Linux | `debian` (mapped) | `apt_to_cyclonedx.py` |
| Alpine Linux | `alpine` | `apk_to_cyclonedx.py` |

---

## Jump Host / Bastion Examples

```bash
# Single-hop jump
python3 sbom_orchestrator.py --host 10.30.0.100 --user deploy \
    -J bastion@10.20.0.1

# Jump host on non-standard port
python3 sbom_orchestrator.py --host 10.30.0.100 --user deploy \
    -J bastion@10.20.0.1:2222

# Multi-hop chain
python3 sbom_orchestrator.py --host 10.40.0.50 --user root \
    -J "jump1@10.20.0.1,jump2@10.30.0.1"

# Jump host with separate key
python3 sbom_orchestrator.py --host 10.30.0.100 --user deploy \
    -J bastion@10.20.0.1 --jump-key ~/.ssh/bastion_key --key ~/.ssh/target_key
```

---

## Sudo Discovery

The `--sudo` flag enables privileged file-system traversal:

```bash
python3 sbom_orchestrator.py --host 10.20.0.5 --user deploy --sudo
```

**What it does:**
- Runs `sudo -n true` to verify passwordless sudo is available.
- Prefixes `find` and `ls` commands with `sudo` so the orchestrator can
  read `/root`, other users' home directories, and restricted paths.
- Discovers virtualenvs, lockfiles, and pyenv/pipx/poetry environments
  across **all** user accounts.

**Requirements:** The remote user must have `NOPASSWD` sudo configured.

---

## Project Structure

```
├── sbom_orchestrator.py       # Master orchestrator (SSH → extract → convert → scan)
├── rpm_to_cyclonedx.py        # RPM → CycloneDX (RHEL 7)
├── dpkg_to_cyclonedx.py       # dpkg → CycloneDX (Debian/Ubuntu)
├── apt_to_cyclonedx.py        # APT → CycloneDX (Debian/Ubuntu/Kali)
├── apk_to_cyclonedx.py        # APK → CycloneDX (Alpine)
├── yum_to_cyclonedx.py        # YUM/DNF → CycloneDX (RHEL, CentOS, Fedora, …)
├── snap_to_cyclonedx.py       # Snap → CycloneDX
├── pip_to_cyclonedx.py        # pip → CycloneDX (with venv support)
├── gem_to_cyclonedx.py        # gem → CycloneDX
├── npm_to_cyclonedx.py        # npm/yarn → CycloneDX
├── go_to_cyclonedx.py         # Go modules → CycloneDX
├── cargo_to_cyclonedx.py      # Cargo → CycloneDX
├── composer_to_cyclonedx.py   # Composer → CycloneDX
├── maven_to_cyclonedx.py      # Maven/Gradle → CycloneDX
├── nuget_to_cyclonedx.py      # NuGet → CycloneDX
├── README.md                  # This file
├── INSTALL.md                 # Installation guide
├── LICENSE                    # MIT License
└── .gitignore
```

---

## Requirements

| Tool | Required For | Install |
|---|---|---|
| Python 3.6+ | All scripts | Pre-installed on most Linux |
| `ssh` / `scp` | Orchestrator | Pre-installed on most Linux |
| `sshpass` | Password auth only | `apt install sshpass` |
| `trivy` | Vulnerability scanning | [trivy.dev/getting-started](https://trivy.dev/latest/getting-started/installation/) |

No Python packages need to be installed — the toolkit uses only the
standard library.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
details.
