#!/usr/bin/env python3
"""
SBOM Orchestrator — Autonomous Remote SBOM Generation & Vulnerability Scanning.

This module provides a fully autonomous pipeline that:

1. Connects to a remote Linux host via SSH (with optional jump-host / bastion
   support via ``ProxyJump``).
2. Detects the operating system and all installed package managers — both
   OS-level (rpm, dpkg, apk, yum/dnf, snap) and language-level (pip, gem,
   npm, go, cargo, composer, maven, nuget, conda, pyenv, pipx).
3. Extracts raw package listings from each discovered source.
4. Converts every listing to a `CycloneDX 1.5 <https://cyclonedx.org/>`_
   SBOM in JSON format using the companion ``*_to_cyclonedx.py`` converter
   scripts.
5. Optionally runs `Trivy <https://trivy.dev/>`_ against each generated
   SBOM and writes per-source JSON vulnerability reports.
6. Produces a final ``summary.json`` with totals and per-source breakdowns.

Authentication modes:
    * **SSH key** (``--key``):  Direct path to a private key.
    * **Interactive password** (``--ask-pass``): Secure prompt via ``getpass``
      — password never appears in shell history or process listings.
    * **Password** (``--password``): Via ``sshpass`` (must be installed).
      Note: visible in process list / shell history.
    * **SSH agent / config**: If neither ``--key`` nor ``--password`` is
      given, the script falls back to ``ssh-agent`` or ``~/.ssh/config``.
    * **Auto-prompt on failure**: If key/agent auth fails and no password
      was given, the user is prompted interactively before aborting.

Requirements:
    * ``ssh`` / ``scp`` on the local machine.
    * ``sshpass`` — only when using ``--password`` auth
      (``apt install sshpass``).
    * ``trivy`` — only when vulnerability scanning is desired
      (omit ``--skip-trivy`` to enable).
    * Python >= 3.6 (standard library only; no third-party packages).

Quick start::

    # SSH key auth:
    python3 sbom_orchestrator.py --host 10.20.0.5 --user root --key ~/.ssh/id_rsa

    # Secure interactive password prompt (never in history):
    python3 sbom_orchestrator.py --host 10.20.0.5 --user admin --ask-pass

    # Password auth (inline — visible in history):
    python3 sbom_orchestrator.py --host 10.20.0.5 --user admin --password 'S3cret!'

    # Via jump host with sudo discovery:
    python3 sbom_orchestrator.py --host 10.30.0.100 --user deploy \
        -J bastion@10.20.0.1 --sudo

    # SOCKS proxy for Trivy DB downloads (air-gapped):
    python3 sbom_orchestrator.py --host 10.20.0.5 --user root \
        --trivy-proxy socks5://127.0.0.1:1080

    # Generate SBOMs only (skip Trivy):
    python3 sbom_orchestrator.py --host 10.20.0.5 --user root --skip-trivy

Output structure::

    sbom_<host>_<timestamp>/
    ├── raw/            # Raw package listings fetched from the remote host
    ├── sbom/           # CycloneDX 1.5 JSON SBOMs (one per source)
    ├── reports/        # Trivy vulnerability reports (JSON)
    └── summary.json    # Aggregated results with component & vuln counts

See Also:
    Individual converter modules in the same directory provide standalone
    CLI usage.  Run ``python3 <converter>.py --help`` for each.
"""

__version__ = "1.0.0"
__author__ = "SBOM Toolkit Contributors"
__license__ = "MIT"

import argparse
import getpass
import json
import os
import subprocess
import sys
import shutil
import re
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Directory where the *_to_cyclonedx.py converter scripts live
# (default: same directory as this orchestrator)
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent

# Map of converter scripts
CONVERTERS = {
    "rpm":      SCRIPT_DIR / "rpm_to_cyclonedx.py",
    "dpkg":     SCRIPT_DIR / "dpkg_to_cyclonedx.py",
    "apk":      SCRIPT_DIR / "apk_to_cyclonedx.py",
    "apt":      SCRIPT_DIR / "apt_to_cyclonedx.py",
    "yum":      SCRIPT_DIR / "yum_to_cyclonedx.py",
    "snap":     SCRIPT_DIR / "snap_to_cyclonedx.py",
    "pip":      SCRIPT_DIR / "pip_to_cyclonedx.py",
    "gem":      SCRIPT_DIR / "gem_to_cyclonedx.py",
    "npm":      SCRIPT_DIR / "npm_to_cyclonedx.py",
    "go":       SCRIPT_DIR / "go_to_cyclonedx.py",
    "cargo":    SCRIPT_DIR / "cargo_to_cyclonedx.py",
    "composer": SCRIPT_DIR / "composer_to_cyclonedx.py",
    "maven":    SCRIPT_DIR / "maven_to_cyclonedx.py",
    "nuget":    SCRIPT_DIR / "nuget_to_cyclonedx.py",
}


# ═══════════════════════════════════════════════════════════════════════════
# SSH helpers
# ═══════════════════════════════════════════════════════════════════════════

class RemoteHost:
    """SSH/SCP wrapper for executing commands and transferring files on a remote host.

    Encapsulates all SSH connection parameters (host, user, port, key,
    password) and optional jump-host configuration so that every call
    to :meth:`run`, :meth:`fetch`, or :meth:`run_and_save` reuses the
    same connection profile.

    Jump-host / bastion support:
        Uses ``-o ProxyJump=…`` so that OpenSSH handles the proxying
        natively.  Both single-hop and multi-hop chains are supported::

            RemoteHost(…, jump="bastion@10.0.0.1")                  # single hop
            RemoteHost(…, jump="bastion@10.0.0.1:2222")             # non-standard port
            RemoteHost(…, jump="jump1@h1,jump2@h2")                 # multi-hop

    Authentication priority:
        1. Explicit ``--password`` → uses ``sshpass -p``.
        2. Explicit ``--key`` → ``ssh -i <key>``.
        3. No flags → ``BatchMode=yes``, relying on ``ssh-agent`` /
           ``~/.ssh/config``.
        4. If all above fail → interactive password prompt via ``getpass``
           (avoids password exposure in shell history / process listings).

    Args:
        host:           Hostname or IP of the target.
        user:           SSH username.
        password:       SSH password (requires ``sshpass``).
        key:            Path to a private key file.
        port:           SSH port (default ``22``).
        jump:           ProxyJump spec (``user@host[:port]``).
        jump_key:       Separate private key for the jump host.
        jump_password:  Password for the jump host (limited use-case).
    """

    def __init__(self, host, user, password=None, key=None, port=22,
                 jump=None, jump_key=None, jump_password=None):
        self.host = host
        self.user = user
        self.password = password
        self.key = key
        self.port = str(port)
        self.jump = jump              # e.g. "user@bastion" or "u@h1,u@h2"
        self.jump_key = jump_key      # optional separate key for the jump host
        self.jump_password = jump_password

        # Base SSH options (applied to the final target connection)
        #   BatchMode=yes: never prompt for passwords interactively.
        #   Enabled when using key auth OR agent auth (no password given).
        #   Disabled only when sshpass is supplying a password.
        use_batch = not password
        self.ssh_opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=15",
            "-o", f"BatchMode={'yes' if use_batch else 'no'}",
            "-p", self.port,
        ]
        if key:
            self.ssh_opts += ["-i", key]

        # Jump host / ProxyJump configuration
        if jump:
            self.ssh_opts += ["-o", f"ProxyJump={jump}"]
            # If a separate key is provided for the jump host, we need to
            # make it available.  SSH will use it for the proxy connection
            # when the jump spec doesn't include a key.
            if jump_key:
                self.ssh_opts += ["-o", f"IdentityFile={jump_key}"]

    def _wrap_cmd(self, base_cmd):
        """Optionally prepend ``sshpass`` for password-based authentication.

        Args:
            base_cmd: The ``ssh`` or ``scp`` command list to wrap.

        Returns:
            The original *base_cmd* if key/agent auth is in use, or the
            same command prefixed with ``['sshpass', '-p', <password>]``.

        Note:
            Jump-host passwords are a special case; they require either
            ``ssh-agent`` with keys loaded or a ``ProxyCommand`` using
            ``sshpass`` (handled via ``--jump-password``).
        """
        if self.password:
            return ["sshpass", "-p", self.password] + base_cmd
        return base_cmd

    def run(self, command, timeout=120, check=False):
        """Execute a shell command on the remote host.

        Args:
            command:  Shell command string to run inside ``ssh``.
            timeout:  Seconds before the subprocess is killed (default 120).
            check:    Unused; reserved for future ``subprocess.check_call`` mode.

        Returns:
            Tuple of ``(returncode, stdout, stderr)``.
            Returns ``(-1, '', 'SSH command timed out')`` on timeout.

        Raises:
            SystemExit: If ``sshpass`` is required but not installed.
        """
        cmd = self._wrap_cmd(
            ["ssh"] + self.ssh_opts + [f"{self.user}@{self.host}", command]
        )
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "SSH command timed out"
        except FileNotFoundError as e:
            if "sshpass" in str(e):
                print("ERROR: sshpass not found. Install it: apt install sshpass", file=sys.stderr)
                sys.exit(1)
            raise

    def fetch(self, remote_path, local_path):
        """Download a single file from the remote host via ``scp``.

        Automatically converts the ``-p PORT`` SSH option to ``-P PORT``
        (capital P) as required by the ``scp`` CLI.

        Args:
            remote_path: Absolute path on the remote host.
            local_path:  Local destination path (file or directory).

        Returns:
            ``True`` on success, ``False`` otherwise.
        """
        # Build SCP options: convert -p PORT to -P PORT for scp
        scp_opts = []
        skip_next = False
        for i, opt in enumerate(self.ssh_opts):
            if skip_next:
                skip_next = False
                continue
            if opt == "-p":
                scp_opts += ["-P", self.ssh_opts[i + 1]]
                skip_next = True
            else:
                scp_opts.append(opt)

        cmd = self._wrap_cmd(
            ["scp"] + scp_opts +
            [f"{self.user}@{self.host}:{remote_path}", str(local_path)]
        )
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode == 0

    def run_and_save(self, command, local_path, timeout=120):
        """Execute a remote command and write stdout to a local file.

        Combines :meth:`run` and a local file write in a single call,
        which is more convenient (and slightly more efficient) than
        calling ``run()`` followed by a manual write.

        Args:
            command:    Shell command string to run.
            local_path: Where to save the output (created/overwritten).
            timeout:    Seconds before the subprocess is killed.

        Returns:
            ``True`` if the command succeeded and produced non-empty
            output; ``False`` otherwise.
        """
        rc, stdout, stderr = self.run(command, timeout=timeout)
        if rc == 0 and stdout.strip():
            Path(local_path).write_text(stdout)
            return True
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Remote detection
# ═══════════════════════════════════════════════════════════════════════════

def detect_os_release(remote):
    """Fetch and parse ``/etc/os-release`` (or ``/usr/lib/os-release``) from the remote.

    Args:
        remote: A :class:`RemoteHost` instance.

    Returns:
        A dict with keys ``ID``, ``VERSION_ID``, ``PRETTY_NAME``, ``ID_LIKE``
        (empty strings for missing keys).
    """
    rc, stdout, _ = remote.run("cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null")
    info = {"ID": "", "VERSION_ID": "", "PRETTY_NAME": "", "ID_LIKE": ""}
    if rc == 0:
        for line in stdout.splitlines():
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v.strip().strip('"')
    return info


def detect_package_managers(remote, use_sudo=False):
    """Probe the remote host for available package managers, venvs, and lockfiles.

    Executes a single compound shell command over SSH that:

    * Checks ``command -v`` for 20+ package managers.
    * Searches common directories for Python virtualenvs (``bin/activate``),
      pyenv versions, pipx venvs, Poetry venvs.
    * Locates lockfiles: ``Cargo.lock``, ``composer.lock``, ``package-lock.json``,
      ``yarn.lock``, ``go.sum``, ``packages.lock.json``, ``pom.xml``.

    Args:
        remote:    A :class:`RemoteHost` instance.
        use_sudo:  When ``True``, prefix ``find``/``ls`` commands with ``sudo``
                   so that privileged directories (``/root``, other users'
                   homes) are accessible.  Requires ``NOPASSWD`` sudo on the
                   remote host.

    Returns:
        A 2-tuple ``(managers, extras)``:

        * **managers** — ``dict[str, bool]`` indicating which package
          managers are installed (``rpm``, ``dpkg``, ``pip``, ...).
        * **extras** — ``dict[str, list[str]]`` with discovered paths:
          ``venvs``, ``pyenv_versions``, ``cargo_locks``, ``composer_locks``,
          ``npm_locks``, ``go_sums``, ``nuget_locks``, ``pom_xmls``.
    """

    # sudo prefix for privileged directory traversal
    S = "sudo " if use_sudo else ""

    # Directories to search — covers standard and non-standard locations
    SEARCH_DIRS = "/opt /home /srv /var /root /usr/local /data /tmp /run"

    # One compound command to check everything in a single SSH round-trip
    probe_script = rf"""
echo "::CHECK_START::"
command -v rpm >/dev/null 2>&1       && echo "HAS_RPM=1"       || echo "HAS_RPM=0"
command -v dpkg >/dev/null 2>&1      && echo "HAS_DPKG=1"      || echo "HAS_DPKG=0"
command -v apt >/dev/null 2>&1       && echo "HAS_APT=1"       || echo "HAS_APT=0"
command -v yum >/dev/null 2>&1       && echo "HAS_YUM=1"       || echo "HAS_YUM=0"
command -v dnf >/dev/null 2>&1       && echo "HAS_DNF=1"       || echo "HAS_DNF=0"
command -v apk >/dev/null 2>&1       && echo "HAS_APK=1"       || echo "HAS_APK=0"
command -v snap >/dev/null 2>&1      && echo "HAS_SNAP=1"      || echo "HAS_SNAP=0"
command -v pip3 >/dev/null 2>&1      && echo "HAS_PIP3=1"      || echo "HAS_PIP3=0"
command -v pip >/dev/null 2>&1       && echo "HAS_PIP=1"       || echo "HAS_PIP=0"
command -v gem >/dev/null 2>&1       && echo "HAS_GEM=1"       || echo "HAS_GEM=0"
command -v npm >/dev/null 2>&1       && echo "HAS_NPM=1"       || echo "HAS_NPM=0"
command -v go >/dev/null 2>&1        && echo "HAS_GO=1"        || echo "HAS_GO=0"
command -v cargo >/dev/null 2>&1     && echo "HAS_CARGO=1"     || echo "HAS_CARGO=0"
command -v composer >/dev/null 2>&1  && echo "HAS_COMPOSER=1"  || echo "HAS_COMPOSER=0"
command -v mvn >/dev/null 2>&1       && echo "HAS_MVN=1"       || echo "HAS_MVN=0"
command -v gradle >/dev/null 2>&1    && echo "HAS_GRADLE=1"    || echo "HAS_GRADLE=0"
command -v dotnet >/dev/null 2>&1    && echo "HAS_DOTNET=1"    || echo "HAS_DOTNET=0"
command -v conda >/dev/null 2>&1     && echo "HAS_CONDA=1"     || echo "HAS_CONDA=0"
command -v pyenv >/dev/null 2>&1     && echo "HAS_PYENV=1"     || echo "HAS_PYENV=0"
command -v pipx >/dev/null 2>&1      && echo "HAS_PIPX=1"      || echo "HAS_PIPX=0"

# ── Virtualenv discovery (bin/activate pattern) ──
{S}find {SEARCH_DIRS} -maxdepth 6 -type f -name 'activate' -path '*/bin/activate' 2>/dev/null | head -50 | while read -r f; do
  echo "VENV=$(dirname "$(dirname "$f")")"
done

# ── pyenv versions (each version dir has a bin/python) ──
# Check PYENV_ROOT, then common locations for all users
for pyroot in "$PYENV_ROOT" "$HOME/.pyenv" /home/*/.pyenv /root/.pyenv /opt/pyenv /usr/local/pyenv; do
  if [ -d "$pyroot/versions" ] 2>/dev/null; then
    {S}ls -d "$pyroot/versions"/*/envs/*/bin/activate 2>/dev/null | while read -r f; do
      echo "VENV=$(dirname "$(dirname "$f")")"
    done
    # Also report pyenv-managed Python installs (not virtualenvs, but
    # they may have pip-installed packages)
    {S}ls -d "$pyroot/versions"/*/bin/pip 2>/dev/null | while read -r f; do
      ver_dir=$(dirname "$(dirname "$f")")
      echo "PYENV_VER=$ver_dir"
    done
  fi
done

# ── pipx venvs ──
for pipx_home in "$HOME/.local/pipx/venvs" /home/*/.local/pipx/venvs /root/.local/pipx/venvs; do
  {S}ls -d "$pipx_home"/*/bin/activate 2>/dev/null | while read -r f; do
    echo "VENV=$(dirname "$(dirname "$f")")"
  done
done

# ── Poetry venvs ──
for poetry_cache in "$HOME/.cache/pypoetry/virtualenvs" /home/*/.cache/pypoetry/virtualenvs /root/.cache/pypoetry/virtualenvs; do
  {S}ls -d "$poetry_cache"/*/bin/activate 2>/dev/null | while read -r f; do
    echo "VENV=$(dirname "$(dirname "$f")")"
  done
done

# ── Check for Cargo.lock files ──
{S}find {SEARCH_DIRS} -maxdepth 5 -name 'Cargo.lock' 2>/dev/null | head -20 | while read -r f; do
  echo "CARGO_LOCK=$f"
done
# ── Check for composer.lock files ──
{S}find {SEARCH_DIRS} -maxdepth 5 -name 'composer.lock' 2>/dev/null | head -20 | while read -r f; do
  echo "COMPOSER_LOCK=$f"
done
# ── Check for package-lock.json / yarn.lock ──
{S}find {SEARCH_DIRS} -maxdepth 5 \( -name 'package-lock.json' -o -name 'yarn.lock' \) 2>/dev/null | head -20 | while read -r f; do
  echo "NPM_LOCK=$f"
done
# ── Check for go.sum ──
{S}find {SEARCH_DIRS} -maxdepth 5 -name 'go.sum' 2>/dev/null | head -20 | while read -r f; do
  echo "GO_SUM=$f"
done
# ── Check for packages.lock.json (.NET) ──
{S}find {SEARCH_DIRS} -maxdepth 5 -name 'packages.lock.json' 2>/dev/null | head -20 | while read -r f; do
  echo "NUGET_LOCK=$f"
done
# ── Check for pom.xml (Maven) ──
{S}find {SEARCH_DIRS} -maxdepth 5 -name 'pom.xml' 2>/dev/null | head -20 | while read -r f; do
  echo "POM_XML=$f"
done
echo "::CHECK_END::"
"""
    rc, stdout, _ = remote.run(probe_script, timeout=180)

    result = {
        "rpm": False, "dpkg": False, "apt": False, "yum": False, "dnf": False,
        "apk": False, "snap": False, "pip": False, "gem": False, "npm": False,
        "go": False, "cargo": False, "composer": False, "mvn": False,
        "gradle": False, "dotnet": False, "conda": False,
        "pyenv": False, "pipx": False,
    }
    venvs = []
    pyenv_versions = []
    cargo_locks = []
    composer_locks = []
    npm_locks = []
    go_sums = []
    nuget_locks = []
    pom_xmls = []

    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("HAS_") and "=" in line:
            key, val = line.split("=", 1)
            mgr = key.replace("HAS_", "").lower()
            # Map pip3 -> pip
            if mgr == "pip3":
                result["pip"] = val == "1"
            elif mgr in result:
                result[mgr] = val == "1"
        elif line.startswith("VENV="):
            path = line.split("=", 1)[1].strip()
            if path and path not in venvs:
                venvs.append(path)
        elif line.startswith("PYENV_VER="):
            path = line.split("=", 1)[1].strip()
            if path and path not in pyenv_versions:
                pyenv_versions.append(path)
        elif line.startswith("CARGO_LOCK="):
            cargo_locks.append(line.split("=", 1)[1].strip())
        elif line.startswith("COMPOSER_LOCK="):
            composer_locks.append(line.split("=", 1)[1].strip())
        elif line.startswith("NPM_LOCK="):
            npm_locks.append(line.split("=", 1)[1].strip())
        elif line.startswith("GO_SUM="):
            go_sums.append(line.split("=", 1)[1].strip())
        elif line.startswith("NUGET_LOCK="):
            nuget_locks.append(line.split("=", 1)[1].strip())
        elif line.startswith("POM_XML="):
            pom_xmls.append(line.split("=", 1)[1].strip())

    return result, {
        "venvs": venvs,
        "pyenv_versions": pyenv_versions,
        "cargo_locks": cargo_locks,
        "composer_locks": composer_locks,
        "npm_locks": npm_locks,
        "go_sums": go_sums,
        "nuget_locks": nuget_locks,
        "pom_xmls": pom_xmls,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Extraction commands — run remotely, save output locally
# ═══════════════════════════════════════════════════════════════════════════

def extract_rpm(remote, outdir):
    """Extract RPM package list in 11-field pipe-delimited format.

    Args:
        remote: :class:`RemoteHost` instance.
        outdir: :class:`~pathlib.Path` to the ``raw/`` directory.

    Returns:
        Path to the saved file on success, ``None`` on failure.
    """
    cmd = r"rpm -qa --queryformat '%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}|%{VENDOR}|%{PACKAGER}|%{SOURCERPM}|%{SIGPGP:pgpsig}|%{BUILDTIME}|%{INSTALLTIME}\n' 2>/dev/null | sort"
    out = outdir / "rpm_packages.txt"
    if remote.run_and_save(cmd, out):
        return out
    return None


def extract_dpkg(remote, outdir):
    """Extract dpkg package list in 8-field pipe-delimited format.

    Args:
        remote: :class:`RemoteHost` instance.
        outdir: :class:`~pathlib.Path` to the ``raw/`` directory.

    Returns:
        Path to the saved file on success, ``None`` on failure.
    """
    cmd = r"dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Maintainer}|${Source}|${Homepage}|${Installed-Size}|${Section}\n' 2>/dev/null | sort"
    out = outdir / "dpkg_packages.txt"
    if remote.run_and_save(cmd, out):
        return out
    return None


def extract_apt(remote, outdir):
    """Extract APT package list via ``apt list --installed``.

    Args:
        remote: :class:`RemoteHost` instance.
        outdir: :class:`~pathlib.Path` to the ``raw/`` directory.

    Returns:
        Path to the saved file on success, ``None`` on failure.
    """
    cmd = "apt list --installed 2>/dev/null | grep -v '^Listing'"
    out = outdir / "apt_packages.txt"
    if remote.run_and_save(cmd, out):
        return out
    return None


def extract_apk(remote, outdir):
    """Extract Alpine APK package list from ``/lib/apk/db/installed``.

    Uses an inline ``awk`` script to parse the APK database into
    pipe-delimited records.

    Args:
        remote: :class:`RemoteHost` instance.
        outdir: :class:`~pathlib.Path` to the ``raw/`` directory.

    Returns:
        Path to the saved file on success, ``None`` on failure.
    """
    # Use the awk script from apk_to_cyclonedx.py
    cmd = r"""awk '
    /^P:/{name=$0; sub(/^P:/,"",name)}
    /^V:/{ver=$0; sub(/^V:/,"",ver)}
    /^A:/{arch=$0; sub(/^A:/,"",arch)}
    /^T:/{desc=$0; sub(/^T:/,"",desc)}
    /^U:/{url=$0; sub(/^U:/,"",url)}
    /^L:/{lic=$0; sub(/^L:/,"",lic)}
    /^o:/{origin=$0; sub(/^o:/,"",origin)}
    /^m:/{maint=$0; sub(/^m:/,"",maint)}
    /^t:/{btime=$0; sub(/^t:/,"",btime)}
    /^$/{if(name!="" && ver!="") print name"|"ver"|"arch"|"desc"|"url"|"lic"|"origin"|"maint"|"btime; name="";ver="";arch="";desc="";url="";lic="";origin="";maint="";btime=""}
    END{if(name!="" && ver!="") print name"|"ver"|"arch"|"desc"|"url"|"lic"|"origin"|"maint"|"btime}
    ' /lib/apk/db/installed 2>/dev/null"""
    out = outdir / "apk_packages.txt"
    if remote.run_and_save(cmd, out):
        return out
    return None


def extract_yum(remote, outdir, has_dnf=False):
    """Extract YUM/DNF package list, preferring ``rpm -qa`` for rich metadata.

    Falls back to ``dnf list installed`` or ``yum list installed`` if
    ``rpm -qa`` returns nothing.

    Args:
        remote:  :class:`RemoteHost` instance.
        outdir:  :class:`~pathlib.Path` to the ``raw/`` directory.
        has_dnf: If ``True``, use ``dnf`` as the fallback instead of ``yum``.

    Returns:
        Path to the saved file on success, ``None`` on failure.
    """
    # Prefer rpm -qa for richer output; fall back to yum/dnf
    cmd = r"rpm -qa --queryformat '%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}|%{VENDOR}|%{PACKAGER}|%{SOURCERPM}|%{SIGPGP:pgpsig}|%{BUILDTIME}|%{INSTALLTIME}\n' 2>/dev/null | sort"
    out = outdir / "yum_packages.txt"
    if remote.run_and_save(cmd, out):
        return out
    # Fallback
    fallback = "dnf list installed 2>/dev/null" if has_dnf else "yum list installed 2>/dev/null"
    if remote.run_and_save(fallback, out):
        return out
    return None


def extract_snap(remote, outdir):
    """Extract snap package list via ``snap list``.

    Args:
        remote: :class:`RemoteHost` instance.
        outdir: :class:`~pathlib.Path` to the ``raw/`` directory.

    Returns:
        Path to the saved file on success, ``None`` on failure.
    """
    cmd = "snap list 2>/dev/null"
    out = outdir / "snap_packages.txt"
    if remote.run_and_save(cmd, out):
        return out
    return None


def extract_pip_system(remote, outdir):
    """Extract system-wide pip packages as JSON (``pip3 list --format json``).

    Args:
        remote: :class:`RemoteHost` instance.
        outdir: :class:`~pathlib.Path` to the ``raw/`` directory.

    Returns:
        Path to the saved JSON file on success, ``None`` on failure.
    """
    # Try pip3 first, then pip
    cmd = "pip3 list --format json 2>/dev/null || pip list --format json 2>/dev/null"
    out = outdir / "pip_system_packages.json"
    if remote.run_and_save(cmd, out):
        return out
    return None


def extract_pip_user(remote, outdir):
    """Extract user-installed pip packages (``pip3 list --user --format json``).

    Skips writing if the result is an empty JSON list ``[]``.

    Args:
        remote: :class:`RemoteHost` instance.
        outdir: :class:`~pathlib.Path` to the ``raw/`` directory.

    Returns:
        Path to the saved JSON file on success, ``None`` on failure.
    """
    cmd = "pip3 list --user --format json 2>/dev/null || pip list --user --format json 2>/dev/null"
    out = outdir / "pip_user_packages.json"
    rc, stdout, _ = remote.run(cmd)
    if rc == 0 and stdout.strip() and stdout.strip() != "[]":
        Path(out).write_text(stdout)
        return out
    return None


def extract_pip_venv(remote, outdir, venv_path):
    """Extract pip packages from a specific virtualenv.

    Tries direct ``<venv>/bin/pip list --format json`` first, then falls
    back to ``<venv>/bin/python -m pip list``.

    Args:
        remote:    :class:`RemoteHost` instance.
        outdir:    :class:`~pathlib.Path` to the ``raw/`` directory.
        venv_path: Absolute path to the virtualenv root on the remote host.

    Returns:
        Tuple of ``(path, venv_path)``; *path* is ``None`` on failure.
    """
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', venv_path.strip('/'))
    cmd = f'"{venv_path}/bin/pip" list --format json 2>/dev/null'
    out = outdir / f"pip_venv_{safe_name}.json"
    if remote.run_and_save(cmd, out):
        return out, venv_path
    # Try python -m pip as fallback
    cmd2 = f'"{venv_path}/bin/python" -m pip list --format json 2>/dev/null'
    if remote.run_and_save(cmd2, out):
        return out, venv_path
    return None, venv_path


def extract_pip_conda(remote, outdir):
    """Discover conda environments and extract pip packages from each.

    Args:
        remote: :class:`RemoteHost` instance.
        outdir: :class:`~pathlib.Path` to the ``raw/`` directory.

    Returns:
        List of ``(path, env_path)`` tuples for each environment that
        yielded packages.
    """
    rc, stdout, _ = remote.run(
        'conda env list --json 2>/dev/null | python3 -c "import sys,json; [print(e) for e in json.load(sys.stdin).get(\'envs\',[])]"'
    )
    results = []
    if rc == 0 and stdout.strip():
        for env_path in stdout.strip().splitlines():
            env_path = env_path.strip()
            if not env_path:
                continue
            safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', env_path.strip('/'))
            cmd = f'"{env_path}/bin/pip" list --format json 2>/dev/null'
            out = outdir / f"pip_conda_{safe}.json"
            if remote.run_and_save(cmd, out):
                results.append((out, env_path))
    return results


def extract_pip_pyenv(remote, outdir, pyenv_ver_path):
    """Extract pip packages from a pyenv-managed Python version.

    Args:
        remote:         :class:`RemoteHost` instance.
        outdir:         :class:`~pathlib.Path` to the ``raw/`` directory.
        pyenv_ver_path: Path to the pyenv version directory (e.g.
                        ``~/.pyenv/versions/3.11.4``).

    Returns:
        Tuple of ``(path, pyenv_ver_path)``; *path* is ``None`` on failure.
    """
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', pyenv_ver_path.strip('/'))
    # Try pip directly in the pyenv version's bin dir
    cmd = f'"{pyenv_ver_path}/bin/pip" list --format json 2>/dev/null'
    out = outdir / f"pip_pyenv_{safe_name}.json"
    if remote.run_and_save(cmd, out):
        return out, pyenv_ver_path
    # Try python -m pip
    cmd2 = f'"{pyenv_ver_path}/bin/python" -m pip list --format json 2>/dev/null'
    if remote.run_and_save(cmd2, out):
        return out, pyenv_ver_path
    return None, pyenv_ver_path


def extract_gem(remote, outdir):
    """Extract locally installed Ruby gems via ``gem list --local``.

    Args:
        remote: :class:`RemoteHost` instance.
        outdir: :class:`~pathlib.Path` to the ``raw/`` directory.

    Returns:
        Path to the saved file on success, ``None`` on failure.
    """
    cmd = "gem list --local 2>/dev/null"
    out = outdir / "gem_packages.txt"
    if remote.run_and_save(cmd, out):
        return out
    return None


def extract_npm_global(remote, outdir):
    """Extract globally installed npm packages as JSON.

    ``npm list`` may exit with code 1 for peer-dependency warnings;
    this is treated as success if the JSON body contains dependencies.

    Args:
        remote: :class:`RemoteHost` instance.
        outdir: :class:`~pathlib.Path` to the ``raw/`` directory.

    Returns:
        Path to the saved JSON file on success, ``None`` on failure.
    """
    cmd = "npm list --global --json 2>/dev/null"
    out = outdir / "npm_global_packages.json"
    rc, stdout, _ = remote.run(cmd)
    if rc in (0, 1) and stdout.strip():  # npm returns 1 for peer dep warnings
        try:
            data = json.loads(stdout)
            if data.get("dependencies"):
                Path(out).write_text(stdout)
                return out
        except json.JSONDecodeError:
            pass
    return None


def extract_npm_lockfile(remote, outdir, lock_path):
    """Fetch a ``package-lock.json`` or ``yarn.lock`` from the remote host.

    Args:
        remote:    :class:`RemoteHost` instance.
        outdir:    :class:`~pathlib.Path` to the ``raw/`` directory.
        lock_path: Absolute path on the remote host.

    Returns:
        Tuple of ``(local_path, lock_path)``; *local_path* is ``None``
        on failure.
    """
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', lock_path.strip('/'))
    ext = "json" if lock_path.endswith(".json") else "lock"
    out = outdir / f"npm_project_{safe}.{ext}"
    if remote.fetch(lock_path, out):
        return out, lock_path
    return None, lock_path


def extract_go_modules(remote, outdir, go_sum_path):
    """Fetch a ``go.sum`` file from the remote host.

    Args:
        remote:      :class:`RemoteHost` instance.
        outdir:      :class:`~pathlib.Path` to the ``raw/`` directory.
        go_sum_path: Absolute path on the remote host.

    Returns:
        Tuple of ``(local_path, go_sum_path)``; *local_path* is ``None``
        on failure.
    """
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', go_sum_path.strip('/'))
    out = outdir / f"go_project_{safe}.sum"
    if remote.fetch(go_sum_path, out):
        return out, go_sum_path
    return None, go_sum_path


def extract_cargo_lock(remote, outdir, lock_path):
    """Fetch a ``Cargo.lock`` file from the remote host.

    Args:
        remote:    :class:`RemoteHost` instance.
        outdir:    :class:`~pathlib.Path` to the ``raw/`` directory.
        lock_path: Absolute path on the remote host.

    Returns:
        Tuple of ``(local_path, lock_path)``; *local_path* is ``None``
        on failure.
    """
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', lock_path.strip('/'))
    out = outdir / f"cargo_project_{safe}.lock"
    if remote.fetch(lock_path, out):
        return out, lock_path
    return None, lock_path


def extract_composer_lock(remote, outdir, lock_path):
    """Fetch a ``composer.lock`` file from the remote host.

    Args:
        remote:    :class:`RemoteHost` instance.
        outdir:    :class:`~pathlib.Path` to the ``raw/`` directory.
        lock_path: Absolute path on the remote host.

    Returns:
        Tuple of ``(local_path, lock_path)``; *local_path* is ``None``
        on failure.
    """
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', lock_path.strip('/'))
    out = outdir / f"composer_project_{safe}.lock"
    if remote.fetch(lock_path, out):
        return out, lock_path
    return None, lock_path


def extract_nuget_lock(remote, outdir, lock_path):
    """Fetch a ``packages.lock.json`` (.NET) from the remote host.

    Args:
        remote:    :class:`RemoteHost` instance.
        outdir:    :class:`~pathlib.Path` to the ``raw/`` directory.
        lock_path: Absolute path on the remote host.

    Returns:
        Tuple of ``(local_path, lock_path)``; *local_path* is ``None``
        on failure.
    """
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', lock_path.strip('/'))
    out = outdir / f"nuget_project_{safe}.json"
    if remote.fetch(lock_path, out):
        return out, lock_path
    return None, lock_path


def extract_maven_deps(remote, outdir, pom_path):
    """Run ``mvn dependency:list`` against a ``pom.xml`` on the remote host.

    Args:
        remote:   :class:`RemoteHost` instance.
        outdir:   :class:`~pathlib.Path` to the ``raw/`` directory.
        pom_path: Absolute path to the ``pom.xml`` on the remote host.

    Returns:
        Tuple of ``(local_path, pom_dir)``; *local_path* is ``None``
        on failure.
    """
    pom_dir = os.path.dirname(pom_path)
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', pom_dir.strip('/'))
    cmd = f'cd "{pom_dir}" && mvn dependency:list -DincludeScope=runtime -DoutputAbsoluteArtifactFileName=false 2>/dev/null'
    out = outdir / f"maven_project_{safe}.txt"
    if remote.run_and_save(cmd, out, timeout=300):
        return out, pom_dir
    return None, pom_dir


# ═══════════════════════════════════════════════════════════════════════════
# Local conversion and scanning
# ═══════════════════════════════════════════════════════════════════════════

def run_converter(converter_key, input_file, output_file, extra_args=None):
    """Invoke one of the ``*_to_cyclonedx.py`` converter scripts as a subprocess.

    Args:
        converter_key: Key into :data:`CONVERTERS` (e.g. ``'rpm'``, ``'pip'``).
        input_file:    Path to the raw package listing.
        output_file:   Destination for the CycloneDX JSON SBOM.
        extra_args:    Optional list of additional CLI flags for the converter.

    Returns:
        ``True`` if the converter exited with code 0, ``False`` otherwise.
    """
    script = CONVERTERS.get(converter_key)
    if not script or not script.exists():
        print(f"  WARNING: Converter script not found: {converter_key}", file=sys.stderr)
        return False

    cmd = [sys.executable, str(script), "-i", str(input_file), "-o", str(output_file)]
    if extra_args:
        cmd.extend(extra_args)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode == 0:
        # Print converter stderr (it logs component count there)
        if result.stderr.strip():
            for line in result.stderr.strip().splitlines():
                print(f"  {line}")
        return True
    else:
        print(f"  CONVERTER ERROR: {result.stderr.strip()}", file=sys.stderr)
        return False


def run_trivy(sbom_file, report_file, proxy=None, skip_db_update=True):
    """Run Trivy in SBOM-scan mode and write a JSON vulnerability report.

    Args:
        sbom_file:      Path to a CycloneDX JSON SBOM.
        report_file:    Where to write the Trivy JSON report.
        proxy:          Optional proxy URL (e.g. ``socks5://127.0.0.1:1080``)
                        injected as ``ALL_PROXY`` / ``HTTPS_PROXY``.
        skip_db_update: If ``True`` (default), pass ``--skip-db-update`` to
                        Trivy so it uses the locally cached vulnerability DB.

    Returns:
        * ``int >= 0`` — number of vulnerabilities found.
        * ``-1`` — Trivy failed or was not found.
        * ``False`` — Trivy binary not in ``PATH``.
    """
    trivy = shutil.which("trivy")
    if not trivy:
        print("  WARNING: trivy not found in PATH — skipping scan", file=sys.stderr)
        return False

    cmd = [trivy, "sbom"]
    if skip_db_update:
        cmd.append("--skip-db-update")
    cmd.extend(["--format", "json", "-o", str(report_file), "--quiet", str(sbom_file)])

    env = os.environ.copy()
    if proxy:
        env["ALL_PROXY"] = proxy
        env["HTTPS_PROXY"] = proxy

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
    if result.returncode == 0:
        # Count vulnerabilities
        try:
            report = json.loads(Path(report_file).read_text())
            total_vulns = 0
            for r in report.get("Results", []):
                total_vulns += len(r.get("Vulnerabilities", []))
            return total_vulns
        except (json.JSONDecodeError, FileNotFoundError):
            return 0
    else:
        stderr = result.stderr.strip()
        if stderr:
            print(f"  TRIVY WARNING: {stderr[:200]}", file=sys.stderr)
        return -1


# ═══════════════════════════════════════════════════════════════════════════
# Pipeline: extract → convert → scan
# ═══════════════════════════════════════════════════════════════════════════

def process_item(label, converter_key, pkg_file, sbom_file, report_file,
                 extra_converter_args=None, trivy_proxy=None, skip_trivy=False):
    """End-to-end pipeline for a single package source.

    Validates the raw input, converts it to a CycloneDX SBOM via the
    appropriate converter, optionally scans it with Trivy, and returns
    a result dict.

    Args:
        label:                Human-readable label (e.g. ``'pip (venv: myapp)'``).
        converter_key:        Key into :data:`CONVERTERS`.
        pkg_file:             Path to the raw package listing.
        sbom_file:            Destination for the CycloneDX SBOM.
        report_file:          Destination for the Trivy JSON report.
        extra_converter_args: Additional CLI args forwarded to the converter.
        trivy_proxy:          Proxy URL for Trivy DB downloads.
        skip_trivy:           If ``True``, skip the Trivy scan step.

    Returns:
        A dict with keys ``label``, ``sbom``, ``components``, ``report``,
        ``vulns`` on success; ``None`` if the input was empty or conversion
        failed.
    """
    print(f"\n{'─'*60}")
    print(f"  [{label}]")
    print(f"  Package file : {pkg_file}")

    # Validate input has content
    content = Path(pkg_file).read_text().strip()
    if not content or content == "[]":
        print(f"  SKIP: Empty package listing")
        return None

    # Convert
    print(f"  SBOM output  : {sbom_file}")
    ok = run_converter(converter_key, pkg_file, sbom_file, extra_converter_args)
    if not ok:
        print(f"  FAIL: Conversion failed")
        return None

    # Check SBOM has components
    try:
        sbom_data = json.loads(Path(sbom_file).read_text())
        comp_count = len(sbom_data.get("components", []))
        if comp_count == 0:
            print(f"  SKIP: SBOM has 0 components")
            return None
        print(f"  Components   : {comp_count}")
    except (json.JSONDecodeError, FileNotFoundError):
        pass

    # Trivy scan
    if skip_trivy:
        print(f"  Trivy scan   : SKIPPED (--skip-trivy)")
        return {"label": label, "sbom": str(sbom_file), "components": comp_count,
                "report": None, "vulns": 0}

    print(f"  Trivy report : {report_file}")
    vuln_count = run_trivy(sbom_file, report_file, proxy=trivy_proxy)
    if vuln_count is None or vuln_count < 0:
        print(f"  Trivy scan   : FAILED")
        return {"label": label, "sbom": str(sbom_file), "components": comp_count,
                "report": None, "vulns": 0}

    print(f"  Vulns found  : {vuln_count}")
    return {"label": label, "sbom": str(sbom_file), "components": comp_count,
            "report": str(report_file), "vulns": vuln_count}


# ═══════════════════════════════════════════════════════════════════════════
# Determine OS family / distro args for converters
# ═══════════════════════════════════════════════════════════════════════════

def os_to_converter_args(os_info):
    """Map ``/etc/os-release`` fields to converter CLI arguments.

    Determines the OS family (``rpm``, ``deb``, or ``apk``) and returns
    the distro ID and version that the converter scripts expect.

    Args:
        os_info: Dict returned by :func:`detect_os_release`.

    Returns:
        Dict with keys ``family``, ``distro``, ``version``.
    """
    os_id = os_info.get("ID", "").lower()
    version = os_info.get("VERSION_ID", "")
    id_like = os_info.get("ID_LIKE", "").lower()

    # Determine distro family
    if os_id in ("rhel", "centos", "rocky", "almalinux", "ol", "fedora", "amzn", "amazon"):
        return {"family": "rpm", "distro": os_id, "version": version}
    if os_id in ("debian", "ubuntu", "kali", "linuxmint", "pop"):
        return {"family": "deb", "distro": os_id, "version": version}
    if os_id == "alpine":
        return {"family": "apk", "distro": os_id, "version": version}

    # Check ID_LIKE
    if "rhel" in id_like or "fedora" in id_like or "centos" in id_like:
        return {"family": "rpm", "distro": os_id, "version": version}
    if "debian" in id_like or "ubuntu" in id_like:
        return {"family": "deb", "distro": os_id, "version": version}

    return {"family": "unknown", "distro": os_id, "version": version}


# ═══════════════════════════════════════════════════════════════════════════
# Host-list file parser
# ═══════════════════════════════════════════════════════════════════════════

def _resolve_key(key_path):
    """Expand ``~`` and environment variables in a key path."""
    if key_path:
        return str(Path(os.path.expandvars(os.path.expanduser(key_path))).resolve())
    return None


def parse_host_list(path):
    """Parse a host-list file and return ``(defaults, hosts)``.

    Supported format: **JSON** with the structure::

        {
          "defaults": {                   // optional — global fallbacks
            "user": "admin",
            "key":  "~/.ssh/id_rsa",
            "port": 22,
            "sudo": true,
            ...
          },
          "hosts": [
            // minimal — inherits all defaults
            { "host": "10.20.0.5" },

            // full override
            {
              "host": "10.20.0.18",
              "user": "deploy",
              "key":  "~/.ssh/deploy_key",
              "password": null,
              "ask_pass": true,
              "port": 22,
              "jump": "bastion@10.20.0.1",
              "jump_key": null,
              "jump_password": null,
              "sudo": false,
              "skip_trivy": false,
              "skip_lang": false,
              "skip_lockfiles": false,
              "outdir": null,
              "trivy_proxy": null
            }
          ]
        }

    Args:
        path: Filesystem path to the JSON host-list file.

    Returns:
        Tuple of ``(defaults_dict, list_of_host_dicts)``.

    Raises:
        SystemExit: On parse errors or missing required fields.
    """
    list_path = Path(path)
    if not list_path.exists():
        print(f"FATAL: Host list file not found: {path}", file=sys.stderr)
        sys.exit(1)

    try:
        data = json.loads(list_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"FATAL: Invalid JSON in host list: {exc}", file=sys.stderr)
        sys.exit(1)

    if isinstance(data, list):
        # Shorthand: bare list of host objects (no defaults block)
        data = {"defaults": {}, "hosts": data}

    defaults = data.get("defaults", {})
    hosts = data.get("hosts", [])

    if not hosts:
        print("FATAL: Host list contains no hosts", file=sys.stderr)
        sys.exit(1)

    # Validate every entry has at least a host
    for idx, entry in enumerate(hosts):
        if isinstance(entry, str):
            # Allow plain strings as shorthand: "10.20.0.5"
            hosts[idx] = {"host": entry}
            entry = hosts[idx]
        if "host" not in entry:
            print(f"FATAL: Host list entry #{idx+1} missing 'host' field: {entry}",
                  file=sys.stderr)
            sys.exit(1)

    return defaults, hosts


def _build_host_cfg(defaults, host_entry, cli_args):
    """Merge CLI args → list defaults → per-host overrides into one config dict.

    Priority (highest to lowest):
        1. Per-host fields in the list file.
        2. ``defaults`` block in the list file.
        3. CLI flags (global fallbacks).

    Returns:
        A ``dict`` with all keys needed by :func:`audit_host`.
    """
    # Start with CLI values as base
    cfg = {
        "host":           None,
        "user":           cli_args.user,
        "password":       cli_args.password,
        "ask_pass":       cli_args.ask_pass,
        "key":            cli_args.key,
        "port":           cli_args.port or 22,
        "jump":           cli_args.jump,
        "jump_key":       cli_args.jump_key,
        "jump_password":  cli_args.jump_password,
        "outdir":         cli_args.outdir,
        "trivy_proxy":    cli_args.trivy_proxy,
        "skip_trivy":     cli_args.skip_trivy,
        "skip_lang":      cli_args.skip_lang,
        "skip_lockfiles": cli_args.skip_lockfiles,
        "sudo":           cli_args.sudo,
    }
    # Layer list-level defaults
    for k, v in defaults.items():
        if v is not None:
            cfg[k] = v
    # Layer per-host overrides (highest priority)
    for k, v in host_entry.items():
        if v is not None:
            cfg[k] = v

    # Resolve key paths
    cfg["key"] = _resolve_key(cfg.get("key"))
    cfg["jump_key"] = _resolve_key(cfg.get("jump_key"))

    # Validate minimum requirements
    if not cfg.get("host"):
        print("FATAL: No host specified", file=sys.stderr)
        sys.exit(1)
    if not cfg.get("user"):
        print(f"FATAL: No user specified for host {cfg['host']}", file=sys.stderr)
        sys.exit(1)

    return cfg


# ═══════════════════════════════════════════════════════════════════════════
# Single-host audit engine
# ═══════════════════════════════════════════════════════════════════════════

def audit_host(cfg, interactive=True):
    """Run the full SBOM audit pipeline against a single remote host.

    Args:
        cfg: Configuration dict with keys: host, user, password, ask_pass,
             key, port, jump, jump_key, jump_password, outdir, trivy_proxy,
             skip_trivy, skip_lang, skip_lockfiles, sudo.
        interactive: If ``True``, prompt for a password on auth failure.
                     Set to ``False`` for unattended batch runs where
                     ``ask_pass`` was not set.

    Returns:
        ``0`` on success, ``1`` on failure.
    """
    host     = cfg["host"]
    user     = cfg["user"]
    password = cfg.get("password")
    ask_pass = cfg.get("ask_pass", False)
    key      = cfg.get("key")
    port     = cfg.get("port", 22)
    jump     = cfg.get("jump")
    jump_key = cfg.get("jump_key")
    jump_password = cfg.get("jump_password")
    outdir_override = cfg.get("outdir")
    trivy_proxy    = cfg.get("trivy_proxy")
    skip_trivy     = cfg.get("skip_trivy", False)
    skip_lang      = cfg.get("skip_lang", False)
    skip_lockfiles = cfg.get("skip_lockfiles", False)
    use_sudo       = cfg.get("sudo", False)

    # ── Interactive password prompt (ask_pass) ────────────────────────
    if ask_pass:
        if password:
            print("Warning: ask_pass overrides password", file=sys.stderr)
        password = getpass.getpass(prompt=f"SSH password for {user}@{host}: ")

    if not password and not key:
        for default_name in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"):
            candidate = Path.home() / ".ssh" / default_name
            if candidate.exists():
                key = str(candidate)
                print(f"Using default SSH key: {key}")
                break
        if not key:
            print("No key or password supplied; relying on ssh-agent / SSH config")

    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if outdir_override:
        outdir = Path(outdir_override)
    else:
        safe_host = re.sub(r'[^a-zA-Z0-9_.-]', '_', host)
        outdir = Path(f"sbom_{safe_host}_{timestamp}")
    outdir.mkdir(parents=True, exist_ok=True)
    raw_dir = outdir / "raw"
    sbom_dir = outdir / "sbom"
    report_dir = outdir / "reports"
    raw_dir.mkdir(exist_ok=True)
    sbom_dir.mkdir(exist_ok=True)
    report_dir.mkdir(exist_ok=True)

    print("=" * 60)
    print(f"  SBOM Orchestrator")
    print(f"  Target    : {user}@{host}:{port}")
    if jump:
        print(f"  Jump via  : {jump}")
    auth_method = 'key' if key else ('password' if password else 'agent/config')
    print(f"  Auth      : {auth_method}")
    print(f"  Output    : {outdir}")
    print(f"  Trivy     : {'skip' if skip_trivy else 'enabled'}")
    print(f"  Sudo      : {'yes' if use_sudo else 'no'}")
    print("=" * 60)

    # ── Connect and test ──────────────────────────────────────────────
    remote = RemoteHost(
        host=host, user=user, password=password, key=key, port=port,
        jump=jump, jump_key=jump_key, jump_password=jump_password,
    )

    print("\n[1/5] Testing SSH connectivity...")
    rc, stdout, stderr = remote.run("echo OK")
    if rc != 0 or "OK" not in stdout:
        if not password and not ask_pass and interactive:
            print(f"  SSH connection failed: {stderr.strip()}")
            print("  Prompting for password (will not be stored in history)...")
            try:
                pwd = getpass.getpass(prompt=f"SSH password for {user}@{host}: ")
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.", file=sys.stderr)
                return 1
            if pwd:
                password = pwd
                remote = RemoteHost(
                    host=host, user=user, password=password, key=key,
                    port=port, jump=jump, jump_key=jump_key,
                    jump_password=jump_password,
                )
                rc, stdout, stderr = remote.run("echo OK")
                if rc != 0 or "OK" not in stdout:
                    print(f"FATAL: Cannot connect to {host}: {stderr.strip()}",
                          file=sys.stderr)
                    return 1
                auth_method = 'password (interactive)'
                print(f"  SSH connection successful (password auth)")
            else:
                print(f"FATAL: Cannot connect to {host}: {stderr.strip()}",
                      file=sys.stderr)
                return 1
        else:
            print(f"FATAL: Cannot connect to {host}: {stderr.strip()}",
                  file=sys.stderr)
            return 1
    else:
        print("  SSH connection successful")

    # ── Detect OS ─────────────────────────────────────────────────────
    print("\n[2/5] Detecting remote OS...")
    os_info = detect_os_release(remote)
    os_args = os_to_converter_args(os_info)
    print(f"  OS          : {os_info.get('PRETTY_NAME', 'unknown')}")
    print(f"  ID          : {os_info.get('ID', '?')}")
    print(f"  Version     : {os_info.get('VERSION_ID', '?')}")
    print(f"  Family      : {os_args['family']}")

    # Save os-release for reference
    (raw_dir / "os-release.txt").write_text(
        "\n".join(f"{k}={v}" for k, v in os_info.items()) + "\n"
    )

    # ── Detect package managers ───────────────────────────────────────
    if use_sudo:
        rc2, stdout2, stderr2 = remote.run("sudo -n true 2>/dev/null && echo SUDO_OK || echo SUDO_FAIL")
        if "SUDO_OK" not in stdout2:
            print("  WARNING: sudo requested but passwordless sudo not available.")
            print("           Falling back to non-sudo discovery.")
            use_sudo = False
        else:
            print("  sudo      : available (NOPASSWD)")

    print("\n[3/5] Detecting package managers...")
    managers, lockfiles = detect_package_managers(remote, use_sudo=use_sudo)

    detected = [m for m, present in managers.items() if present]
    print(f"  Managers    : {', '.join(detected) if detected else 'none'}")
    print(f"  Virtualenvs : {len(lockfiles['venvs'])}")
    if lockfiles['pyenv_versions']:
        print(f"  pyenv vers  : {len(lockfiles['pyenv_versions'])}")
    if not skip_lockfiles:
        for kind, paths in lockfiles.items():
            if kind != "venvs" and paths:
                print(f"  {kind:14s}: {len(paths)} found")

    # ── Extract ───────────────────────────────────────────────────────
    print("\n[4/5] Extracting package listings from remote host...")
    results = []

    # ── OS-level package managers ──
    # RPM (standalone, not via yum — for RHEL/CentOS/Fedora)
    if managers["rpm"] and os_args["family"] == "rpm":
        print("\n  Extracting RPM packages...")
        pkg_file = extract_rpm(remote, raw_dir)
        if pkg_file:
            extra = ["--distro", os_args["distro"], "--distro-version", os_args["version"]] \
                if os_args["version"] else []
            # Use yum converter for RPM-based distros (it handles all variants)
            r = process_item(
                label=f"RPM ({os_args['distro']})",
                converter_key="yum",
                pkg_file=pkg_file,
                sbom_file=sbom_dir / "sbom_rpm.cdx.json",
                report_file=report_dir / "trivy_rpm.json",
                extra_converter_args=extra,
                trivy_proxy=trivy_proxy,
                skip_trivy=skip_trivy,
            )
            if r:
                results.append(r)

    # DPKG
    if managers["dpkg"] and os_args["family"] == "deb":
        print("\n  Extracting dpkg packages...")
        pkg_file = extract_dpkg(remote, raw_dir)
        if pkg_file:
            extra = []
            if os_args["distro"]:
                extra += ["--distro", os_args["distro"]]
            if os_args["version"]:
                extra += ["--distro-version", os_args["version"]]
            r = process_item(
                label=f"dpkg ({os_args['distro']})",
                converter_key="dpkg",
                pkg_file=pkg_file,
                sbom_file=sbom_dir / "sbom_dpkg.cdx.json",
                report_file=report_dir / "trivy_dpkg.json",
                extra_converter_args=extra,
                trivy_proxy=trivy_proxy,
                skip_trivy=skip_trivy,
            )
            if r:
                results.append(r)

    # APK (Alpine)
    if managers["apk"] and os_args["family"] == "apk":
        print("\n  Extracting APK packages...")
        pkg_file = extract_apk(remote, raw_dir)
        if pkg_file:
            extra = []
            if os_args["version"]:
                extra += ["--alpine-version", os_args["version"]]
            r = process_item(
                label="APK (Alpine)",
                converter_key="apk",
                pkg_file=pkg_file,
                sbom_file=sbom_dir / "sbom_apk.cdx.json",
                report_file=report_dir / "trivy_apk.json",
                extra_converter_args=extra,
                trivy_proxy=trivy_proxy,
                skip_trivy=skip_trivy,
            )
            if r:
                results.append(r)

    # Snap
    if managers["snap"]:
        print("\n  Extracting snap packages...")
        pkg_file = extract_snap(remote, raw_dir)
        if pkg_file:
            extra = []
            if os_args["distro"]:
                extra += ["--distro", os_args["distro"]]
            if os_args["version"]:
                extra += ["--distro-version", os_args["version"]]
            r = process_item(
                label="snap",
                converter_key="snap",
                pkg_file=pkg_file,
                sbom_file=sbom_dir / "sbom_snap.cdx.json",
                report_file=report_dir / "trivy_snap.json",
                extra_converter_args=extra,
                trivy_proxy=trivy_proxy,
                skip_trivy=skip_trivy,
            )
            if r:
                results.append(r)

    # ── Language-level package managers ──
    if not skip_lang:

        # System pip
        if managers["pip"]:
            print("\n  Extracting pip (system) packages...")
            pkg_file = extract_pip_system(remote, raw_dir)
            if pkg_file:
                r = process_item(
                    label="pip (system)",
                    converter_key="pip",
                    pkg_file=pkg_file,
                    sbom_file=sbom_dir / "sbom_pip_system.cdx.json",
                    report_file=report_dir / "trivy_pip_system.json",
                    extra_converter_args=["--venv-name", "system"],
                    trivy_proxy=trivy_proxy,
                    skip_trivy=skip_trivy,
                )
                if r:
                    results.append(r)

            # User pip
            print("  Extracting pip (user) packages...")
            pkg_file = extract_pip_user(remote, raw_dir)
            if pkg_file:
                r = process_item(
                    label="pip (user)",
                    converter_key="pip",
                    pkg_file=pkg_file,
                    sbom_file=sbom_dir / "sbom_pip_user.cdx.json",
                    report_file=report_dir / "trivy_pip_user.json",
                    extra_converter_args=["--venv-name", "user-site"],
                    trivy_proxy=trivy_proxy,
                    skip_trivy=skip_trivy,
                )
                if r:
                    results.append(r)

        # Virtual environments
        for venv_path in lockfiles["venvs"]:
            venv_name = os.path.basename(venv_path)
            safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', venv_path.strip('/'))
            print(f"\n  Extracting pip (venv: {venv_path})...")
            pkg_file, _ = extract_pip_venv(remote, raw_dir, venv_path)
            if pkg_file:
                r = process_item(
                    label=f"pip (venv: {venv_name})",
                    converter_key="pip",
                    pkg_file=pkg_file,
                    sbom_file=sbom_dir / f"sbom_pip_venv_{safe}.cdx.json",
                    report_file=report_dir / f"trivy_pip_venv_{safe}.json",
                    extra_converter_args=[
                        "--venv-name", venv_name,
                        "--venv-path", venv_path,
                    ],
                    trivy_proxy=trivy_proxy,
                    skip_trivy=skip_trivy,
                )
                if r:
                    results.append(r)

        # Conda environments
        if managers["conda"]:
            print("\n  Discovering conda environments...")
            conda_results = extract_pip_conda(remote, raw_dir)
            for pkg_file, env_path in conda_results:
                env_name = os.path.basename(env_path)
                safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', env_path.strip('/'))
                r = process_item(
                    label=f"pip (conda: {env_name})",
                    converter_key="pip",
                    pkg_file=pkg_file,
                    sbom_file=sbom_dir / f"sbom_pip_conda_{safe}.cdx.json",
                    report_file=report_dir / f"trivy_pip_conda_{safe}.json",
                    extra_converter_args=[
                        "--venv-name", f"conda:{env_name}",
                        "--venv-path", env_path,
                    ],
                    trivy_proxy=trivy_proxy,
                    skip_trivy=skip_trivy,
                )
                if r:
                    results.append(r)

        # pyenv-managed Python versions
        for pyenv_path in lockfiles.get("pyenv_versions", []):
            ver_name = os.path.basename(pyenv_path)
            safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', pyenv_path.strip('/'))
            print(f"\n  Extracting pip (pyenv: {pyenv_path})...")
            pkg_file, _ = extract_pip_pyenv(remote, raw_dir, pyenv_path)
            if pkg_file:
                r = process_item(
                    label=f"pip (pyenv: {ver_name})",
                    converter_key="pip",
                    pkg_file=pkg_file,
                    sbom_file=sbom_dir / f"sbom_pip_pyenv_{safe}.cdx.json",
                    report_file=report_dir / f"trivy_pip_pyenv_{safe}.json",
                    extra_converter_args=[
                        "--venv-name", f"pyenv:{ver_name}",
                        "--venv-path", pyenv_path,
                    ],
                    trivy_proxy=trivy_proxy,
                    skip_trivy=skip_trivy,
                )
                if r:
                    results.append(r)

        # Ruby gems
        if managers["gem"]:
            print("\n  Extracting Ruby gems...")
            pkg_file = extract_gem(remote, raw_dir)
            if pkg_file:
                r = process_item(
                    label="gem (Ruby)",
                    converter_key="gem",
                    pkg_file=pkg_file,
                    sbom_file=sbom_dir / "sbom_gem.cdx.json",
                    report_file=report_dir / "trivy_gem.json",
                    trivy_proxy=trivy_proxy,
                    skip_trivy=skip_trivy,
                )
                if r:
                    results.append(r)

        # npm global
        if managers["npm"]:
            print("\n  Extracting npm (global) packages...")
            pkg_file = extract_npm_global(remote, raw_dir)
            if pkg_file:
                r = process_item(
                    label="npm (global)",
                    converter_key="npm",
                    pkg_file=pkg_file,
                    sbom_file=sbom_dir / "sbom_npm_global.cdx.json",
                    report_file=report_dir / "trivy_npm_global.json",
                    trivy_proxy=trivy_proxy,
                    skip_trivy=skip_trivy,
                )
                if r:
                    results.append(r)

    # ── Lockfile-based extraction ──
    if not skip_lockfiles:

        # npm/yarn lockfiles
        for lock_path in lockfiles.get("npm_locks", []):
            safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', lock_path.strip('/'))
            print(f"\n  Fetching npm lockfile: {lock_path}")
            pkg_file, _ = extract_npm_lockfile(remote, raw_dir, lock_path)
            if pkg_file:
                r = process_item(
                    label=f"npm (project: {os.path.dirname(lock_path)})",
                    converter_key="npm",
                    pkg_file=pkg_file,
                    sbom_file=sbom_dir / f"sbom_npm_{safe}.cdx.json",
                    report_file=report_dir / f"trivy_npm_{safe}.json",
                    trivy_proxy=trivy_proxy,
                    skip_trivy=skip_trivy,
                )
                if r:
                    results.append(r)

        # Go modules
        for go_path in lockfiles.get("go_sums", []):
            safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', go_path.strip('/'))
            print(f"\n  Fetching go.sum: {go_path}")
            pkg_file, _ = extract_go_modules(remote, raw_dir, go_path)
            if pkg_file:
                r = process_item(
                    label=f"go (project: {os.path.dirname(go_path)})",
                    converter_key="go",
                    pkg_file=pkg_file,
                    sbom_file=sbom_dir / f"sbom_go_{safe}.cdx.json",
                    report_file=report_dir / f"trivy_go_{safe}.json",
                    trivy_proxy=trivy_proxy,
                    skip_trivy=skip_trivy,
                )
                if r:
                    results.append(r)

        # Cargo.lock
        for lock_path in lockfiles.get("cargo_locks", []):
            safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', lock_path.strip('/'))
            print(f"\n  Fetching Cargo.lock: {lock_path}")
            pkg_file, _ = extract_cargo_lock(remote, raw_dir, lock_path)
            if pkg_file:
                r = process_item(
                    label=f"cargo (project: {os.path.dirname(lock_path)})",
                    converter_key="cargo",
                    pkg_file=pkg_file,
                    sbom_file=sbom_dir / f"sbom_cargo_{safe}.cdx.json",
                    report_file=report_dir / f"trivy_cargo_{safe}.json",
                    trivy_proxy=trivy_proxy,
                    skip_trivy=skip_trivy,
                )
                if r:
                    results.append(r)

        # composer.lock
        for lock_path in lockfiles.get("composer_locks", []):
            safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', lock_path.strip('/'))
            print(f"\n  Fetching composer.lock: {lock_path}")
            pkg_file, _ = extract_composer_lock(remote, raw_dir, lock_path)
            if pkg_file:
                r = process_item(
                    label=f"composer (project: {os.path.dirname(lock_path)})",
                    converter_key="composer",
                    pkg_file=pkg_file,
                    sbom_file=sbom_dir / f"sbom_composer_{safe}.cdx.json",
                    report_file=report_dir / f"trivy_composer_{safe}.json",
                    trivy_proxy=trivy_proxy,
                    skip_trivy=skip_trivy,
                )
                if r:
                    results.append(r)

        # NuGet packages.lock.json
        for lock_path in lockfiles.get("nuget_locks", []):
            safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', lock_path.strip('/'))
            print(f"\n  Fetching NuGet lock: {lock_path}")
            pkg_file, _ = extract_nuget_lock(remote, raw_dir, lock_path)
            if pkg_file:
                r = process_item(
                    label=f"nuget (project: {os.path.dirname(lock_path)})",
                    converter_key="nuget",
                    pkg_file=pkg_file,
                    sbom_file=sbom_dir / f"sbom_nuget_{safe}.cdx.json",
                    report_file=report_dir / f"trivy_nuget_{safe}.json",
                    trivy_proxy=trivy_proxy,
                    skip_trivy=skip_trivy,
                )
                if r:
                    results.append(r)

        # Maven pom.xml
        if managers["mvn"]:
            for pom_path in lockfiles.get("pom_xmls", []):
                safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', os.path.dirname(pom_path).strip('/'))
                print(f"\n  Running mvn dependency:list on: {pom_path}")
                pkg_file, _ = extract_maven_deps(remote, raw_dir, pom_path)
                if pkg_file:
                    r = process_item(
                        label=f"maven (project: {os.path.dirname(pom_path)})",
                        converter_key="maven",
                        pkg_file=pkg_file,
                        sbom_file=sbom_dir / f"sbom_maven_{safe}.cdx.json",
                        report_file=report_dir / f"trivy_maven_{safe}.json",
                        trivy_proxy=trivy_proxy,
                        skip_trivy=skip_trivy,
                    )
                    if r:
                        results.append(r)

    # ── Summary ───────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  SCAN SUMMARY")
    print("=" * 60)
    print(f"  Host           : {user}@{host}")
    print(f"  OS             : {os_info.get('PRETTY_NAME', 'unknown')}")
    print(f"  Output dir     : {outdir}")
    print(f"  Sources scanned: {len(results)}")

    total_components = 0
    total_vulns = 0

    if results:
        print(f"\n  {'Source':<35s} {'Components':>10s} {'Vulns':>8s}")
        print(f"  {'─'*35} {'─'*10} {'─'*8}")
        for r in results:
            comps = r.get("components", 0)
            vulns = r.get("vulns", 0)
            total_components += comps
            total_vulns += vulns
            print(f"  {r['label']:<35s} {comps:>10d} {vulns:>8d}")
        print(f"  {'─'*35} {'─'*10} {'─'*8}")
        print(f"  {'TOTAL':<35s} {total_components:>10d} {total_vulns:>8d}")
    else:
        print("\n  No packages were extracted.")

    print(f"\n  Output files:")
    print(f"    Raw packages : {raw_dir}/")
    print(f"    SBOM files   : {sbom_dir}/")
    if not skip_trivy:
        print(f"    Trivy reports: {report_dir}/")
    print("=" * 60)

    # Write summary JSON
    summary = {
        "host": host,
        "user": user,
        "timestamp": datetime.now().isoformat(),
        "os": os_info,
        "results": results,
        "totals": {
            "sources": len(results),
            "components": total_components,
            "vulnerabilities": total_vulns,
        },
    }
    summary_file = outdir / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"\n  Summary written to: {summary_file}")

    return 0 if results else 1


# ═══════════════════════════════════════════════════════════════════════════
# Main — CLI entry point with --list support
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="SBOM Orchestrator — autonomous remote package discovery, "
                    "extraction, SBOM generation, and Trivy scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # ── Single-host mode ────────────────────────────────────────
  %(prog)s --host 10.20.0.5 --user root --key ~/.ssh/id_rsa
  %(prog)s --host 10.20.0.5 --user admin --ask-pass
  %(prog)s --host 10.20.0.5 --user admin --password 'S3cret!'
  %(prog)s --host 10.30.0.100 --user deploy -J bastion@10.20.0.1 --sudo

  # ── Batch mode (host list file) ────────────────────────────
  # Global user/key, per-host overrides in JSON:
  %(prog)s --list hosts.json --user admin --key ~/.ssh/id_rsa --sudo

  # Minimal — everything defined in the list file:
  %(prog)s --list hosts.json

Host-list file format (JSON):
  {
    "defaults": {
      "user": "admin",
      "key":  "~/.ssh/id_rsa",
      "sudo": true
    },
    "hosts": [
      { "host": "10.20.0.5" },
      { "host": "10.20.0.18", "user": "deploy", "key": "~/.ssh/deploy_key" },
      { "host": "10.30.0.100", "ask_pass": true, "sudo": false }
    ]
  }

  Or a simple array of host strings / objects:
  ["10.20.0.5", "10.20.0.18", {"host": "10.30.0.100", "user": "root"}]

Priority (highest → lowest):
  per-host fields  >  "defaults" block  >  CLI flags
"""
    )

    # ── Target selection (mutually exclusive) ─────────────────────────
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--host", default=None,
                              help="Remote host IP or hostname (single-host mode)")
    target_group.add_argument("--list", default=None, metavar="FILE",
                              help="Path to a JSON host-list file (batch mode)")

    # ── Auth / connection ─────────────────────────────────────────────
    parser.add_argument("--user", default=None,
                        help="SSH username (required for single-host; default for batch)")
    parser.add_argument("--password", default=None,
                        help="SSH password (requires sshpass) — visible in process list/history")
    parser.add_argument("--ask-pass", action="store_true",
                        help="Prompt for SSH password interactively (secure — never stored in history)")
    parser.add_argument("--key", default=None,
                        help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22,
                        help="SSH port (default: 22)")
    parser.add_argument("-J", "--jump", default=None,
                        help="Jump host(s) for SSH ProxyJump (e.g. user@bastion:port)")
    parser.add_argument("--jump-key", default=None,
                        help="SSH private key for the jump host")
    parser.add_argument("--jump-password", default=None,
                        help="Password for the jump host")

    # ── Output / scanning ─────────────────────────────────────────────
    parser.add_argument("--outdir", default=None,
                        help="Output directory (default: ./sbom_<host>_<timestamp>)")
    parser.add_argument("--trivy-proxy", default=None,
                        help="Proxy URL for Trivy DB downloads")
    parser.add_argument("--skip-trivy", action="store_true",
                        help="Generate SBOMs only, skip Trivy scanning")
    parser.add_argument("--skip-lang", action="store_true",
                        help="Skip language-level package managers")
    parser.add_argument("--skip-lockfiles", action="store_true",
                        help="Skip lockfile discovery")
    parser.add_argument("--sudo", action="store_true",
                        help="Use sudo for privileged discovery")

    args = parser.parse_args()

    # ── Single-host mode ──────────────────────────────────────────────
    if args.host:
        if not args.user:
            parser.error("--user is required in single-host mode")

        cfg = {
            "host":           args.host,
            "user":           args.user,
            "password":       args.password,
            "ask_pass":       args.ask_pass,
            "key":            _resolve_key(args.key),
            "port":           args.port,
            "jump":           args.jump,
            "jump_key":       _resolve_key(args.jump_key),
            "jump_password":  args.jump_password,
            "outdir":         args.outdir,
            "trivy_proxy":    args.trivy_proxy,
            "skip_trivy":     args.skip_trivy,
            "skip_lang":      args.skip_lang,
            "skip_lockfiles": args.skip_lockfiles,
            "sudo":           args.sudo,
        }
        return audit_host(cfg, interactive=True)

    # ── Batch mode (--list) ───────────────────────────────────────────
    defaults, hosts = parse_host_list(args.list)

    total = len(hosts)
    succeeded = 0
    failed = 0
    failed_hosts = []

    print("=" * 60)
    print(f"  SBOM Orchestrator — Batch Mode")
    print(f"  Hosts     : {total}")
    print(f"  List file : {args.list}")
    if defaults:
        print(f"  Defaults  : {json.dumps(defaults, default=str)}")
    print("=" * 60)

    for idx, host_entry in enumerate(hosts, 1):
        cfg = _build_host_cfg(defaults, host_entry, args)
        host_label = f"{cfg.get('user', '?')}@{cfg['host']}"

        print(f"\n{'━' * 60}")
        print(f"  [{idx}/{total}] {host_label}")
        print(f"{'━' * 60}")

        try:
            # In batch mode, only prompt interactively if ask_pass is set
            # for that host (avoid blocking the batch on prompts).
            interactive = cfg.get("ask_pass", False)
            rc = audit_host(cfg, interactive=interactive)
            if rc == 0:
                succeeded += 1
            else:
                failed += 1
                failed_hosts.append(cfg["host"])
        except Exception as exc:
            print(f"  ERROR: {exc}", file=sys.stderr)
            failed += 1
            failed_hosts.append(cfg["host"])

    # ── Batch summary ─────────────────────────────────────────────────
    print(f"\n{'━' * 60}")
    print(f"  BATCH SUMMARY")
    print(f"{'━' * 60}")
    print(f"  Total hosts : {total}")
    print(f"  Succeeded   : {succeeded}")
    print(f"  Failed      : {failed}")
    if failed_hosts:
        print(f"  Failed list : {', '.join(failed_hosts)}")
    print(f"{'━' * 60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
