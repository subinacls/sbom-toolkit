# Installation Guide

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| **Python** | 3.6+ | Standard library only — no `pip install` needed |
| **ssh / scp** | Any | Pre-installed on virtually all Linux distributions |
| **sshpass** | Any | Only required when using `--password` authentication |
| **trivy** | 0.50+ | Only required for vulnerability scanning |

---

## 1. Clone the Repository

```bash
git clone https://github.com/<your-org>/sbom-toolkit.git
cd sbom-toolkit
```

Or download the files directly — there is no build step.

---

## 2. (Optional) Install sshpass

Required only if you plan to use password-based SSH authentication
(`--password` flag):

```bash
# Debian / Ubuntu / Kali
sudo apt install sshpass

# RHEL / CentOS / Fedora
sudo dnf install sshpass

# Alpine
sudo apk add sshpass

# macOS (Homebrew)
brew install hudochenkov/sshpass/sshpass
```

---

## 3. (Optional) Install Trivy

Required only for vulnerability scanning.  Skip this if you only need
SBOM generation (`--skip-trivy`).

### Debian / Ubuntu / Kali

```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
    gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] \
    https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | \
    sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy
```

### RHEL / CentOS / Fedora

```bash
sudo rpm -ivh https://github.com/aquasecurity/trivy/releases/download/v0.52.0/trivy_0.52.0_Linux-64bit.rpm
```

### Alpine

```bash
sudo apk add --no-cache trivy
```

### Binary Download

```bash
# Download the latest release for your platform
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

### Verify Installation

```bash
trivy --version
```

---

## 4. Verify Setup

```bash
# Check Python version
python3 --version   # Should be 3.6+

# Check SSH
ssh -V

# Check sshpass (if needed)
sshpass -V

# Check trivy (if needed)
trivy --version

# Run a quick test (SBOM-only, no Trivy)
python3 sbom_orchestrator.py --host <target_ip> --user <user> --key ~/.ssh/id_rsa --skip-trivy
```

---

## Air-Gapped Environments

If the scanning machine has no internet access, Trivy needs its
vulnerability database pre-loaded.

### Option A: Pre-download the DB

On an internet-connected machine:

```bash
trivy image --download-db-only
# DB is stored at ~/.cache/trivy/db/
```

Copy `~/.cache/trivy/` to the air-gapped machine.

### Option B: SOCKS Proxy

Set up a SOCKS tunnel from the air-gapped machine to one with internet:

```bash
ssh -C -D 1080 -N -f <user>@<internet_host>
```

Then pass the proxy to the orchestrator:

```bash
python3 sbom_orchestrator.py --host <target> --user root \
    --trivy-proxy socks5://127.0.0.1:1080
```

---

## Standalone Converter Usage

Each converter script works independently without the orchestrator:

```bash
# Extract packages on a remote host manually
ssh root@10.20.0.5 "rpm -qa --queryformat '...'" > rpm_packages.txt

# Convert to SBOM
python3 rpm_to_cyclonedx.py -i rpm_packages.txt -o sbom.cdx.json

# Scan with Trivy
trivy sbom --format json -o report.json sbom.cdx.json
```

---

## Uninstall

Simply delete the directory — there are no system-level installations or
configuration files:

```bash
rm -rf sbom-toolkit/
```
