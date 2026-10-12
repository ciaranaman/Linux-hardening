# Linux Hardening Toolkit

Interactive hardening for a full systemd host. Includes two standalone Python 3 entry points:

- **Kali Linux kali-rolling:** [kali-hardening.py](kali-hardening.py), [Kali guide](docs/KALI.md).
- **Ubuntu 22.04/24.04 and Debian 12/13:** [harden.py](harden.py).

Each script is self-contained and uses Python's standard library. Run from a local console
or a host with a working recovery console. Preview is the default; apply requires a flag
and typed confirmation. These are configurable baseline tools, not a CIS/STIG compliance
certification or a substitute for a host-specific threat model.

## Quick start

```sh
git clone https://github.com/ciaranaman/Linux-hardening.git
cd Linux-hardening
# Choose ONE entry point appropriate for this host:
sudo python3 kali-hardening.py
# Ubuntu/Debian:
sudo python3 harden.py
```

The interactive preview prints selected packages, configuration file contents and firewall
exceptions. It runs read-only discovery commands and creates only a temporary coordination
lock in /run; it does not install packages or change persistent configuration.

Review the plan and take a VM/disk snapshot before applying:

```sh
sudo python3 kali-hardening.py --apply
# OR on supported Ubuntu/Debian:
sudo python3 harden.py --apply
```

Apply prompts again rather than executing a saved, potentially stale plan. Type APPLY to
commit the reviewed choices. No passwords or SSH private keys are requested.

## Inputs

- Which modules to enable.
- Management IPv4/IPv6 addresses or CIDRs, when managing SSH/firewall.
- Existing non-root users allowed to log in over SSH.
- Confirmation that a fresh administrator login and sudo have already been tested.
- Whether to require public keys, including confirmation of a successful key login.
- Whether SSH forwarding is required for tunnels/development.
- Public service ports and separate listener ports restricted to the management allowlist.
- Optional auditd, Fail2ban, AppArmor, Lynis, AIDE and ClamAV installations.

Blank public/private port lists expose no additional ports. Use `443/tcp,53/udp`;
port ranges and shell expressions are rejected. A management CIDR may describe an approved
lab network, but the script rejects /0 management ranges. Choose narrow ranges.
When run over SSH, the current client address must be included. Public service ports
intentionally allow any IPv4/IPv6 source; SSH ports cannot be entered as public ports.

## Modules and limits

| Module | Behavior |
| --- | --- |
| SSH | Preserve existing ports; deny root/empty-password logins; require explicit user allowlist; reduce authentication attempts; opt-in public-key-only access and forwarding control |
| Firewall | UFW deny incoming/routed, allow outgoing; dual-stack management and service exceptions; low-level logging |
| Kernel/network | ASLR, pointer/dmesg restrictions, protected links, disabled redirects/source routing and SYN cookies |
| Logging | Persistent journal with storage/retention caps; PAM core-dump limits |
| Audit | Identity, sudo and SSH configuration watches without immutable rules |
| Fail2ban | SSH jail, journald backend, management address exclusions |
| Updates | Ubuntu/Debian unattended security origins, no automatic reboot; Kali rolling updates stay manual |
| AppArmor | Enable packaged profiles; no blanket conversion to enforcement and no custom application profiles |
| Lynis | Install for a separate assessment; recommendations require review |
| AIDE | Install only; baseline creation/approval and check scheduling remain operator tasks |
| ClamAV | Install scanner and signature updater only; no automatic scans, deletion or updater enablement |

No IPv6 disablement, password/PAM lockout rewrites, blanket kernel module blacklist,
partition remounts, offensive-tool removal or automatic system reboot is performed.
SSH forwarding restrictions apply to SSH features; users with shells may create other tunnels.
Password login remains at its existing policy unless public-key-only is chosen.
AppArmor can affect software behavior; review denials before enabling it on lab machines.
Journal caps can discard old evidence; forward logs if retention requirements exceed these caps.
Core limits apply through PAM and do not guarantee all systemd services disable dumps.

## Access protection and refusal conditions

- Existing OpenSSH service and tested administrator access are required for SSH/firewall modules.
  The script does not install or enable an SSH listener that was intentionally disabled.
- Socket-activated SSH is refused for SSH/firewall changes, including hosts where ssh.socket
  owns listening ports. Keep those modules disabled or migrate it in a maintenance procedure.
- `sshd -t` and effective settings for selected users/current source are checked before reload.
  Existing Match blocks, identity providers and cloud settings still need host-specific review.
- Firewall management requires SSH checks. On a local machine without SSH, leave both
  modules off and design its firewall separately.
- An active UFW policy, active Docker/containerd/firewalld/nftables/libvirt service, or
  enabled IPv4/IPv6 routing blocks firewall replacement. Custom packet filters may not be
  discoverable from service status, so the operator must also confirm none exist.
- Docker-published ports can bypass UFW. This tool is not a container/VPN firewall solution.
- Immutable audit configuration blocks audit changes.
- Containers, WSL, NetHunter and hosts without full systemd are not supported.

The allowlist controls host SSH/private service rules and Fail2ban exclusions; it does not
restrict all outbound traffic, validate upstream/cloud firewall rules or guarantee reachability.

## Timed recovery

After package installation and before configuration changes, apply saves root-only state
under `/var/lib/linux-hardening/run-...` and arms a systemd rollback for 10 minutes.
Open a **new** SSH session (or local login/terminal when SSH is not selected), test sudo
and necessary applications, then use the exact command printed by the script:

```sh
sudo python3 kali-hardening.py --confirm /var/lib/linux-hardening/run-EXACT_ID
```

For Ubuntu/Debian, substitute `harden.py`. Confirmation after the deadline is refused.
If confirmation is omitted, the timer attempts configuration restoration. Do not reboot,
shut down, suspend, or disrupt systemd while this transient timer is armed; it is not a
persistent boot recovery mechanism. If apply fails, immediate restoration is attempted.

Manual recovery from the console:

```sh
sudo python3 kali-hardening.py --restore /var/lib/linux-hardening/run-EXACT_ID
```

You can also run the root-owned copy:
`sudo python3 /var/lib/linux-hardening/run-EXACT_ID/harden.py --restore /var/lib/linux-hardening/run-EXACT_ID`.
Use `systemctl status linux-hardening-rollback-EXACT_ID.timer` and its corresponding
.service, plus `restore-result.json`, to inspect recovery.

Recovery restores the snapshotted files, saved runtime sysctl values, UFW state and
selected service states on a best-effort basis. Installed/upgraded packages, dependencies,
package-generated files, journal history and arbitrary package side effects remain.
Audit runtime changes may need a maintenance reboot. The snapshot is taken after package
installation. It is not a full-system transaction; use a VM/disk snapshot for full recovery.
Do not edit managed files concurrently while a recovery timer is armed. An unconfirmed
previous run prevents another apply.

Backups can contain sensitive configuration: keep the state directory private, do not
upload it to GitHub and delete old state only after validating and retaining required evidence.

## Verification

Read-only checks (some commands require the corresponding selected package):

```sh
sudo /usr/sbin/sshd -t
sudo ufw status verbose
sudo fail2ban-client status sshd
sudo auditctl -l
sudo aa-status
journalctl --disk-usage
systemctl list-timers
sudo python3 scripts/report.py
```

`report.py` reports service, socket, user-account, privilege and security-tool state.
Review its output locally; do not publish usernames, IPs or internal service details.

Additional assessments and maintenance:

```sh
sudo lynis audit system
# Run an AIDE baseline only after reviewing /etc/aide and clean-host evidence:
sudo aideinit
# Read your installed aideinit(8) and aide(1) docs before promoting its generated DB.
# Manage ClamAV signatures and schedule a scanner separately if you selected it.
# Ubuntu/Debian selected security-update policy:
sudo unattended-upgrade --dry-run --debug
```

AIDE is not protection until a trustworthy baseline is approved and checks are regularly
run and reviewed. ClamAV is an additional scanner, not a replacement for patching or access control.

## Tests and validation

```sh
python3 -m py_compile harden.py kali-hardening.py scripts/report.py
python3 -m unittest discover -s tests -v
```

Tests cover address/port validation, injection-like inputs, key-only policy selection,
Kali's update boundary, symlink refusal and file restoration behavior. They use temporary
files and mocked commands; they do not harden the test runner.
The included GitHub Actions workflow runs these checks on Ubuntu.

Runtime validation of real package installation, host-specific SSH/Match/cloud settings,
UFW traffic, audit loading and timer recovery **must be performed in disposable target VMs**.
The delivery environment could not execute Python or Linux VMs, so the scripts have not
been runtime certified on the supported distributions. Review before privileged execution.

## Manual security review

The automated modules are one part of a broader baseline. Review:
disk encryption/recovery keys and secure boot; current updates and firmware; unnecessary
listeners/services; sudo privileges and inactive users; SSH authorized keys; systemd/cron jobs;
setuid binaries and writable paths; application secrets; backups/restore drills; log forwarding;
physical/VM console access; DNS/VPN/network trust; and threat-specific application policies.
Avoid universal settings that break laboratory tools or remove your recovery route.

## Sources

- [Kali repositories](https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/)
- [Kali network service policy](https://www.kali.org/docs/policy/kali-linux-network-service-policy/)
- [Kali package updates](https://www.kali.org/docs/general-use/updating-a-package/)
- [Ubuntu OpenSSH](https://ubuntu.com/server/docs/openssh-server/)
- [Ubuntu automatic updates](https://ubuntu.com/server/docs/how-to/software/automatic-updates/)
- [Docker firewall limitations](https://docs.docker.com/engine/network/packet-filtering-firewalls/)

MIT licensed project code. Installed packages retain their own licenses.
