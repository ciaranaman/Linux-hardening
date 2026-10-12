#!/usr/bin/env python3
"""Interactive Ubuntu/Debian hardening. Preview by default; no external Python deps."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid

BASE = Path("/var/lib/linux-hardening")
SSHD = "/usr/sbin/sshd"
PATHS = [
    "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/00-linux-hardening.conf",
    "/etc/ufw", "/etc/default/ufw",
    "/etc/sysctl.d/60-linux-hardening.conf",
    "/etc/security/limits.d/60-linux-hardening.conf",
    "/etc/systemd/journald.conf.d/60-linux-hardening.conf",
    "/etc/apt/apt.conf.d/99-linux-hardening",
    "/etc/fail2ban/jail.d/linux-hardening.local",
    "/etc/audit/rules.d/60-linux-hardening.rules",
]
SYSCTL = {
    "kernel.randomize_va_space": "2", "kernel.kptr_restrict": "2",
    "kernel.dmesg_restrict": "1", "fs.protected_hardlinks": "1",
    "fs.protected_symlinks": "1", "fs.suid_dumpable": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.default.send_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.default.accept_source_route": "0",
    "net.ipv6.conf.all.accept_redirects": "0",
    "net.ipv6.conf.default.accept_redirects": "0",
    "net.ipv6.conf.all.accept_source_route": "0",
    "net.ipv6.conf.default.accept_source_route": "0",
    "net.ipv4.tcp_syncookies": "1",
}
SERVICES = ["fail2ban", "apparmor", "auditd", "apt-daily.timer", "apt-daily-upgrade.timer"]
AUDIT_WATCHES = [("/etc/passwd", "wa", "lh_identity"),
                 ("/etc/shadow", "wa", "lh_identity"),
                 ("/etc/group", "wa", "lh_identity"),
                 ("/etc/sudoers", "wa", "lh_privilege"),
                 ("/etc/sudoers.d", "wa", "lh_privilege"),
                 ("/etc/ssh", "wa", "lh_ssh")]

def run(*args, check=True):
    result = subprocess.run(list(args), text=True, capture_output=True, check=False,
                            env={**os.environ, "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    if check and result.returncode:
        raise RuntimeError(shlex.join(args) + "\n" + result.stdout + result.stderr)
    return result

def networks(value):
    values = [item for item in re.split(r"[,\s]+", value.strip()) if item]
    if not values:
        raise ValueError("Enter at least one IP or CIDR.")
    result = []
    for item in values:
        network = ipaddress.ip_network(item, strict=False)
        if network.prefixlen == 0:
            raise ValueError("An all-addresses management allowlist is not allowed.")
        result.append(str(network))
    return sorted(set(result))

def ports(value):
    result = []
    for item in value.split(","):
        if not item.strip():
            continue
        match = re.fullmatch(r"\s*([0-9]{1,5})/(tcp|udp)\s*", item)
        if not match or not 1 <= int(match[1]) <= 65535:
            raise ValueError("Use individual ports like 443/tcp,53/udp.")
        result.append((int(match[1]), match[2]))
    return sorted(set(result))

def contains(address, ranges):
    ip = ipaddress.ip_address(address)
    return any(ip.version == ipaddress.ip_network(n).version and
               ip in ipaddress.ip_network(n) for n in ranges)

def ask(prompt, default=""):
    answer = input(prompt + (f" [{default}]" if default else "") + ": ").strip()
    return answer or default

def yes(prompt, default=False):
    while True:
        answer = ask(prompt + " (yes/no)", "yes" if default else "no").lower()
        if answer in ("yes", "no"):
            return answer == "yes"

def validated(prompt, parser, default=""):
    while True:
        try:
            return parser(ask(prompt, default))
        except ValueError as exc:
            print(exc)

def osinfo():
    data = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            data[key] = shlex.split(value)[0] if value else ""
    supported = {"ubuntu": {"22.04", "24.04"}, "debian": {"12", "13"}}
    if data.get("VERSION_ID") not in supported.get(data.get("ID"), set()):
        raise RuntimeError("Supported targets: Ubuntu 22.04/24.04, Debian 12/13.")
    if not re.fullmatch(r"[a-z0-9]+", data.get("VERSION_CODENAME", "")):
        raise RuntimeError("Missing or unexpected distribution codename.")
    if not Path("/run/systemd/system").exists():
        raise RuntimeError("A full systemd host is required; containers/WSL are not targets.")
    return data

def collect():
    ssh_connection = os.environ.get("SSH_CONNECTION", "").split()
    current_ip = ssh_connection[0] if len(ssh_connection) == 4 else ""
    print("Preview mode makes no persistent changes. Use a VM snapshot before applying.")
    profile = {}
    profile["ssh"] = yes("Harden an existing OpenSSH server", True)
    profile["firewall"] = yes("Replace inactive UFW rules with a restricted host firewall", True)
    profile["trusted"] = validated("Management IPs/CIDRs, comma separated", networks, current_ip)
    if current_ip and not contains(current_ip, profile["trusted"]):
        raise RuntimeError("Current SSH client IP must be in the management allowlist.")
    profile["ssh_ports"] = []
    if profile["ssh"]:
        if not Path(SSHD).exists():
            raise RuntimeError("Install and test openssh-server first; this tool will not bootstrap remote access.")
        effective = run(SSHD, "-T").stdout
        profile["ssh_ports"] = sorted({int(line.split()[1]) for line in effective.splitlines()
                                      if line.startswith("port ")})
        if not profile["ssh_ports"]:
            raise RuntimeError("Could not determine the existing SSH ports.")
        if ssh_connection and int(ssh_connection[3]) not in profile["ssh_ports"]:
            raise RuntimeError("SSH server port differs from configuration; check socket activation/proxying.")
        print("Preserving SSH ports:", profile["ssh_ports"])
        users = ask("Allowed SSH users, comma separated", os.environ.get("SUDO_USER", ""))
        profile["users"] = [u.strip() for u in users.split(",") if u.strip()]
        if not profile["users"]:
            raise ValueError("At least one existing non-root SSH user is required.")
        for user in profile["users"]:
            if not re.fullmatch(r"[a-z_][a-z0-9_-]*", user) or pwd.getpwnam(user).pw_uid == 0:
                raise ValueError("Use existing non-root local usernames.")
        if not yes("Have you tested SSH login and sudo for one listed administrator"):
            raise RuntimeError("Test administrator access in a separate terminal first.")
        profile["key_only"] = yes("Require public keys (disables password and keyboard-interactive/MFA login)")
        if profile["key_only"] and not yes("Have you tested a fresh public-key login for that administrator"):
            raise RuntimeError("Test public-key access before selecting key-only mode.")
        profile["forwarding"] = yes("Allow SSH forwarding needed for tunnels or development")
    elif profile["firewall"]:
        raise RuntimeError("Firewall changes require SSH checks; otherwise manage the firewall manually.")

    profile["public_ports"] = validated("Public inbound service ports; blank means none", ports)
    if any(port in profile["ssh_ports"] for port, proto in profile["public_ports"]):
        raise ValueError("SSH ports cannot be opened publicly.")
    profile["private_ports"] = validated("Additional ports restricted to management IPs; blank means none", ports)
    for option, label, default in [
        ("sysctl", "Apply kernel/network safeguards (may affect diagnostics)", True),
        ("logging", "Bound persistent journal storage and disable core dumps through PAM limits", True),
        ("audit", "Install auditd and identity/SSH/sudo file watches", True),
        ("fail2ban", "Install Fail2ban for SSH", True),
        ("updates", "Enable unattended security updates without automatic reboot", True),
        ("apparmor", "Install and enable AppArmor using distribution profiles", True),
        ("lynis", "Install Lynis for an on-demand security assessment", True),
        ("aide", "Install AIDE for a manually reviewed integrity baseline", False),
        ("clamav", "Install ClamAV and its signature updater (no scheduled scan)", False),
    ]:
        profile[option] = yes(label, default)
    if profile["fail2ban"] and not profile["ssh"]:
        raise ValueError("Fail2ban requires the SSH module.")
    return profile

def render(profile, distro):
    files = {}
    if profile["ssh"]:
        files[PATHS[1]] = (
            "PermitRootLogin no\nPermitEmptyPasswords no\nPubkeyAuthentication yes\n"
            "MaxAuthTries 3\nLoginGraceTime 30\nX11Forwarding no\n"
            "LogLevel VERBOSE\nAllowUsers " + " ".join(profile["users"]) + "\n"
            "DisableForwarding " + ("no" if profile["forwarding"] else "yes") + "\n")
        if profile["key_only"]:
            files[PATHS[1]] += ("PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
                               "AuthenticationMethods publickey\n")
    if profile["sysctl"]:
        files[PATHS[4]] = "".join(f"{key} = {value}\n" for key, value in SYSCTL.items()
                                if Path("/proc/sys/" + key.replace(".", "/")).exists())
    if profile["logging"]:
        files[PATHS[5]] = "* hard core 0\nroot hard core 0\n"
        files[PATHS[6]] = ("[Journal]\nStorage=persistent\nSystemMaxUse=256M\n"
                          "RuntimeMaxUse=64M\nMaxRetentionSec=30day\n")
    if profile["updates"]:
        origin = "Ubuntu" if distro["ID"] == "ubuntu" else "Debian"
        codename = distro["VERSION_CODENAME"]
        pattern = (f"origin=Ubuntu,archive={codename}-security" if origin == "Ubuntu"
                   else f"origin=Debian,label=Debian-Security,codename={codename}-security")
        files[PATHS[7]] = (
            '#clear Unattended-Upgrade::Allowed-Origins;\n'
            '#clear Unattended-Upgrade::Origins-Pattern;\n'
            f'Unattended-Upgrade::Origins-Pattern {{ "{pattern}"; }};\n'
            'Unattended-Upgrade::Automatic-Reboot "false";\n'
            'APT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "1";\n')
    if profile["fail2ban"]:
        files[PATHS[8]] = ("[sshd]\nenabled = true\nbackend = systemd\n"
                          "banaction = ufw\n" if profile["firewall"] else
                          "[sshd]\nenabled = true\nbackend = systemd\n")
        files[PATHS[8]] += ("port = " + ",".join(map(str, profile["ssh_ports"])) +
                           "\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n"
                           "ignoreip = 127.0.0.1/8 ::1 " + " ".join(profile["trusted"]) + "\n")
    if profile["audit"]:
        files[PATHS[9]] = "".join(f"-w {path} -p {perms} -k {key}\n"
                                 for path, perms, key in AUDIT_WATCHES if Path(path).exists())
    return files

def package_list(profile):
    result = ["ca-certificates"]
    mapping = {"firewall": ["ufw"], "audit": ["auditd"],
               "fail2ban": ["fail2ban", "python3-systemd"],
               "updates": ["unattended-upgrades"],
               "apparmor": ["apparmor", "apparmor-utils"], "lynis": ["lynis"],
               "aide": ["aide"], "clamav": ["clamav", "clamav-freshclam"]}
    for key, packages in mapping.items():
        if profile[key]:
            result.extend(packages)
    return sorted(set(result))

def write(path, content):
    target = Path(path)
    if target.is_symlink():
        raise RuntimeError("Refusing symlink: " + path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".linux-hardening.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()

def secure_state(value):
    path = Path(value)
    if path.parent != BASE or not re.fullmatch(r"run-[a-f0-9]{32}", path.name):
        raise ValueError("Use the exact /var/lib/linux-hardening/run-... path from apply.")
    for item in (BASE, path, path / "manifest.json"):
        if item.is_symlink() or item.stat().st_uid != 0 or item.stat().st_mode & 0o022:
            raise ValueError("Rollback state must be root owned and not writable by other users.")
    return path

def snapshot(profile):
    if BASE.is_symlink():
        raise RuntimeError("Refusing symlink state directory.")
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if BASE.stat().st_uid != 0 or BASE.stat().st_mode & 0o077:
        raise RuntimeError("State directory must be root owned with mode 0700.")
    state = BASE / ("run-" + uuid.uuid4().hex)
    state.mkdir(mode=0o700)
    originals = {}
    for index, value in enumerate(PATHS):
        source = Path(value)
        if source.is_symlink():
            raise RuntimeError("Refusing symlink configuration path: " + value)
        originals[value] = source.exists()
        if source.exists():
            dest = state / str(index)
            if source.is_dir():
                shutil.copytree(source, dest, symlinks=True)
            else:
                shutil.copy2(source, dest)
    manifest = {"originals": originals, "sysctl": {}, "profile": profile,
                "ufw_active": "Status: active" in run("ufw", "status", check=False).stdout
                              if shutil.which("ufw") else False}
    if profile["sysctl"]:
        for key in SYSCTL:
            result = run("sysctl", "-n", key, check=False)
            if result.returncode == 0:
                manifest["sysctl"][key] = result.stdout.strip()
    manifest["services"] = {service: {
        "active": run("systemctl", "is-active", service, check=False).stdout.strip() == "active",
        "enabled": run("systemctl", "is-enabled", service, check=False).stdout.strip() == "enabled"
    } for service in SERVICES}
    write(str(state / "manifest.json"), json.dumps(manifest, indent=2))
    shutil.copy2(Path(__file__).resolve(), state / "harden.py")
    (state / "harden.py").chmod(0o600)
    return state

def timer_name(state):
    return "linux-hardening-rollback-" + state.name[4:]

def restore(state):
    state = secure_state(str(state))
    manifest = json.loads((state / "manifest.json").read_text())
    if set(manifest["originals"]) != set(PATHS):
        raise ValueError("Unexpected rollback manifest paths.")
    errors = []
    for index, value in enumerate(PATHS):
        target = Path(value)
        try:
            if target.is_symlink():
                raise RuntimeError("Refusing symlink during restore: " + value)
            if target.exists():
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            if manifest["originals"][value]:
                source = state / str(index)
                target.parent.mkdir(parents=True, exist_ok=True)
                if source.is_dir():
                    shutil.copytree(source, target, symlinks=True)
                else:
                    shutil.copy2(source, target)
        except Exception as exc:
            errors.append(str(exc))
    for key, value in manifest["sysctl"].items():
        if key not in SYSCTL or not re.fullmatch(r"[0-9]+", value):
            errors.append("Unexpected saved sysctl setting")
            continue
        result = run("sysctl", "-w", f"{key}={value}", check=False)
        if result.returncode:
            errors.append(result.stderr)
    if manifest["profile"]["firewall"]:
        result = run("ufw", "--force", "enable" if manifest["ufw_active"] else "disable", check=False)
        if result.returncode:
            errors.append(result.stderr)
    if manifest["profile"]["ssh"]:
        if run(SSHD, "-t", check=False).returncode == 0:
            result = run("systemctl", "reload", "ssh", check=False)
            if result.returncode:
                errors.append(result.stderr)
        else:
            errors.append("Restored SSH configuration failed validation; use console.")
    if manifest["profile"]["audit"]:
        for path, perms, key in AUDIT_WATCHES:
            run("auditctl", "-W", path, "-p", perms, "-k", key, check=False)
        run("augenrules", "--load", check=False)
    if manifest["profile"]["logging"]:
        run("systemctl", "restart", "systemd-journald", check=False)
    for service, previous in manifest["services"].items():
        selected = (service == "fail2ban" and manifest["profile"]["fail2ban"] or
                    service == "apparmor" and manifest["profile"]["apparmor"] or
                    service == "auditd" and manifest["profile"]["audit"] or
                    service.startswith("apt-daily") and manifest["profile"]["updates"])
        if selected:
            run("systemctl", "enable" if previous["enabled"] else "disable", service, check=False)
            run("systemctl", "restart" if previous["active"] else "stop", service, check=False)
    run("systemctl", "stop", timer_name(state) + ".timer", check=False)
    write(str(state / "restore-result.json"), json.dumps({"errors": errors}, indent=2))
    if errors:
        raise RuntimeError("Restore needs review:\n" + "\n".join(errors))
    print("Configuration restored:", state, "(installed packages and their side effects remain)")

def firewall_checks():
    if shutil.which("ufw") and "Status: active" in run("ufw", "status").stdout:
        raise RuntimeError("Active UFW policy detected. Preserve it by deselecting firewall.")
    for service in ("docker", "containerd", "firewalld", "nftables", "libvirtd"):
        if run("systemctl", "is-active", service, check=False).stdout.strip() == "active":
            raise RuntimeError(service + " is active; deselect firewall and use a workload-aware policy.")
    for proc in ("/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"):
        if Path(proc).exists() and Path(proc).read_text().strip() == "1":
            raise RuntimeError("Routing enabled; deselect firewall on routers/VPN gateways.")
    if not yes("Is this a standalone host with no custom packet-filter rules, containers or VPN routing"):
        raise RuntimeError("Use your existing firewall manager instead.")

def verify_ssh(profile):
    run(SSHD, "-t")
    client = os.environ.get("SSH_CONNECTION", "").split()
    addr = client[0] if client else str(ipaddress.ip_network(profile["trusted"][0]).network_address)
    for user in profile["users"]:
        values = {}
        for line in run(SSHD, "-T", "-C", f"user={user},addr={addr},host=localhost").stdout.splitlines():
            key, _, value = line.partition(" ")
            values[key] = value
        expected = {"permitrootlogin": "no", "pubkeyauthentication": "yes",
                    "disableforwarding": "no" if profile["forwarding"] else "yes"}
        if profile["key_only"]:
            expected.update(passwordauthentication="no", kbdinteractiveauthentication="no",
                            authenticationmethods="publickey")
        for key, value in expected.items():
            if values.get(key) != value:
                raise RuntimeError(f"SSH Match/precedence conflict for {user}: {key}")
        if set(values.get("allowusers", "").split()) != set(profile["users"]):
            raise RuntimeError("SSH AllowUsers differs from requested users.")
    if run("systemctl", "is-active", "ssh.socket", check=False).stdout.strip() == "active":
        raise RuntimeError("SSH socket activation detected. Review it manually before using SSH module.")

def apply(profile, files):
    if profile["firewall"]:
        firewall_checks()
    if profile["ssh"] and run("systemctl", "is-active", "ssh.socket", check=False).stdout.strip() == "active":
        raise RuntimeError("Deselect SSH/firewall on socket-activated hosts; migrate SSH service manually.")
    if profile["audit"] and shutil.which("auditctl") and re.search(r"^enabled 2$", run("auditctl", "-s", check=False).stdout, re.M):
        raise RuntimeError("Immutable audit rules detected; deselect audit and plan a maintenance reboot.")
    print("Installing selected packages from configured, signature-verified APT repositories.")
    run("apt-get", "update")
    # Suppress standard Debian service startup until reviewed configuration is installed.
    policy = Path("/usr/sbin/policy-rc.d")
    own_policy = not policy.exists() and not policy.is_symlink()
    if own_policy:
        write(str(policy), "#!/bin/sh\nexit 101\n")
        policy.chmod(0o755)
    try:
        run("apt-get", "-y", "install", "--no-install-recommends", *package_list(profile))
    finally:
        if own_policy:
            policy.unlink()
    state = snapshot(profile)
    write(str(state / "expires"), str(time.time() + 600))
    run("systemd-run", "--unit=" + timer_name(state), "--on-active=10m",
        "/usr/bin/python3", str(state / "harden.py"), "--restore", str(state))
    print("Rollback armed for 10 minutes. State:", state, flush=True)
    try:
        for path, content in files.items():
            write(path, content)
        if profile["ssh"]:
            main = Path(PATHS[0]).read_text()
            include = "Include " + PATHS[1]
            if main.splitlines()[:1] != [include]:
                write(PATHS[0], include + "\n" + main)
            verify_ssh(profile)
            run("systemctl", "reload", "ssh")
        if profile["sysctl"]:
            # Apply only our settings; do not reload unrelated sysctl files.
            run("sysctl", "-p", PATHS[4])
        if profile["logging"]:
            run("systemctl", "restart", "systemd-journald")
        if profile["firewall"]:
            run("ufw", "--force", "reset")
            config = Path("/etc/default/ufw").read_text()
            if re.search(r"^IPV6=", config, re.M):
                config = re.sub(r"^IPV6=.*$", "IPV6=yes", config, flags=re.M)
            else:
                config += "\nIPV6=yes\n"
            write("/etc/default/ufw", config)
            run("ufw", "default", "deny", "incoming")
            run("ufw", "default", "allow", "outgoing")
            run("ufw", "default", "deny", "routed")
            for source in profile["trusted"]:
                for port in profile["ssh_ports"]:
                    run("ufw", "allow", "from", source, "to", "any", "port", str(port), "proto", "tcp")
                for port, proto in profile["private_ports"]:
                    run("ufw", "allow", "from", source, "to", "any", "port", str(port), "proto", proto)
            for port, proto in profile["public_ports"]:
                run("ufw", "allow", f"{port}/{proto}")
            run("ufw", "logging", "low")
            run("ufw", "--force", "enable")
        if profile["audit"]:
            run("systemctl", "enable", "--now", "auditd")
            run("augenrules", "--load")
        if profile["fail2ban"]:
            run("fail2ban-client", "-t")
            run("systemctl", "enable", "fail2ban")
            run("systemctl", "restart", "fail2ban")
            run("fail2ban-client", "status", "sshd")
        if profile["updates"]:
            run("unattended-upgrade", "--dry-run")
            run("systemctl", "enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer")
        if profile["apparmor"]:
            run("systemctl", "enable", "--now", "apparmor")
            run("aa-status")
        write(str(state / "applied.json"), json.dumps(profile, indent=2))
        print("\nOpen a NEW " + ("SSH session from an allowed address" if profile["ssh"] else "local terminal/login session") + ", test sudo and application access.")
        print("Then cancel rollback from that new session:")
        print("sudo python3 " + str(Path(__file__).resolve()) + " --confirm " + str(state))
        print("Manual restore: sudo python3 " + str(Path(__file__).resolve()) + " --restore " + str(state))
    except BaseException:
        print("Apply failed. Attempting configuration rollback.", file=sys.stderr)
        restore(state)
        raise

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--apply", action="store_true")
    group.add_argument("--restore", metavar="STATE")
    group.add_argument("--confirm", metavar="STATE")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("Run with sudo: preview requires access to SSH configuration.")
    os.umask(0o077)
    # One writer/restore at a time, including the timer-triggered recovery.
    lock = open("/run/linux-hardening.lock", "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX if args.restore else fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError("Another hardening/rollback operation is running.")
    if args.restore:
        restore(Path(args.restore))
        return
    if args.confirm:
        state = secure_state(args.confirm)
        if not (state / "applied.json").exists() or (state / "restore-result.json").exists():
            raise RuntimeError("This run did not complete or has already rolled back.")
        if time.time() >= float((state / "expires").read_text()):
            raise RuntimeError("Rollback deadline elapsed; do not cancel recovery.")
        if run("systemctl", "is-active", timer_name(state) + ".timer", check=False).stdout.strip() != "active":
            raise RuntimeError("Rollback timer is not armed; inspect its service and saved state.")
        if not yes("Has a NEW login/session, sudo, and required application access succeeded"):
            raise RuntimeError("Leave the rollback timer armed.")
        if time.time() >= float((state / "expires").read_text()):
            raise RuntimeError("Rollback deadline elapsed while confirming; leave recovery armed.")
        run("systemctl", "stop", timer_name(state) + ".timer")
        write(str(state / "confirmed"), "Access verified by operator\n")
        print("Rollback cancelled. Keep backups private:", state)
        return
    if args.apply and BASE.exists():
        for old in BASE.glob("run-*"):
            if (old / "manifest.json").exists() and not (old / "confirmed").exists() and not (old / "restore-result.json").exists():
                raise RuntimeError("An unconfirmed previous run exists: " + str(old))
    distro = osinfo()
    profile = collect()
    files = render(profile, distro)
    print("\nPROFILE\n" + json.dumps(profile, indent=2))
    print("\nAPT packages: " + " ".join(package_list(profile)))
    for path, content in files.items():
        print("\n--- " + path + " ---\n" + content)
    print("SSH include (when selected): prepend the managed file to sshd_config.")
    print("Firewall (when selected): deny incoming/routed; allow outgoing; apply listed exceptions.")
    if not args.apply:
        print("PREVIEW COMPLETE. No packages/configuration changes made. Run with --apply to proceed.")
        return
    if ask("Type APPLY to change this host") != "APPLY":
        raise RuntimeError("Apply cancelled.")
    apply(profile, files)

if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        sys.exit(1)
