#!/usr/bin/env python3
"""Read-only local security inventory; keep output private."""
import os
from pathlib import Path
import pwd
import shutil
import subprocess

def show(title, args):
    print("\n== " + title + " ==")
    if not shutil.which(args[0]):
        print("Not installed.")
        return
    result = subprocess.run(args, text=True, capture_output=True, check=False,
                            env={**os.environ, "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    print((result.stdout + result.stderr).strip() or "(no output)")
    if result.returncode:
        print("Exit status:", result.returncode)

def main():
    show("OS", ["cat", "/etc/os-release"])
    show("Listeners", ["ss", "-lntup"])
    show("Running services", ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"])
    show("Timers", ["systemctl", "list-timers", "--all", "--no-pager"])
    show("Firewall", ["ufw", "status", "verbose"])
    show("SSH syntax", ["/usr/sbin/sshd", "-t"])
    show("Fail2ban SSH", ["fail2ban-client", "status", "sshd"])
    show("Audit rules", ["auditctl", "-l"])
    show("AppArmor", ["aa-status"])
    show("Journal disk use", ["journalctl", "--disk-usage"])
    show("Sudo syntax", ["visudo", "-c"])
    print("\n== UID 0 accounts ==")
    print("\n".join(entry.pw_name for entry in pwd.getpwall() if entry.pw_uid == 0))
    print("\n== Interactive local account names ==")
    print("\n".join(entry.pw_name for entry in pwd.getpwall()
                    if entry.pw_shell and not entry.pw_shell.endswith(("nologin", "false"))))
    if os.geteuid() == 0:
        print("\n== Empty local password fields (names only) ==")
        fields = [line.split(":") for line in Path("/etc/shadow").read_text().splitlines()]
        print("\n".join(row[0] for row in fields if len(row) > 1 and not row[1]) or "None.")
    print("\nInventory only: these checks do not certify a hardened system.")

if __name__ == "__main__":
    main()
