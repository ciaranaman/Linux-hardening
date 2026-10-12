# Kali Linux workstation hardening

Use the standalone `kali-hardening.py` for **Kali Linux kali-rolling on a full systemd
VM or installed host**. Do not use it in a forensic live session: applying configuration,
package and log changes would alter evidence. NetHunter, WSL, containers and non-rolling
Kali branches are not supported.

## Run

```sh
sudo python3 kali-hardening.py          # interactive preview
sudo python3 kali-hardening.py --apply  # review prompts, then type APPLY
```

The [main README](../README.md) explains recovery and limitations. Use a snapshot and
console access first. After apply, verify access/application behavior in a new session and
run the printed --confirm command within 10 minutes.

## Kali defaults

| Choice | Default | Reason |
| --- | --- | --- |
| Existing SSH hardening | Off | Kali intentionally avoids starting network listeners by default |
| Firewall replacement | Off | Lab listeners, container networks and VPN routing need a specific policy |
| SSH forwarding, when SSH selected | On | Preserve lab tunnels and proxy workflows |
| Kernel/network safeguards | Off | Redirect/diagnostic changes can alter testing behavior |
| Auditd | Off | File watches can create noise during engagements |
| AppArmor profile enablement | Off | Test interaction with assessment tools before enabling profiles |
| Bounded persistent journal/PAM core limits | On | Useful baseline logging and reduced local core-dump exposure |
| Lynis installation | On | Operator-reviewed security assessment |
| Fail2ban | On only if SSH selected | Protect a deliberately enabled SSH service |
| AIDE/ClamAV | Off | Optional integrity/scanning workflows need explicit setup |
| Unattended rolling upgrades | Never configured | Maintenance windows and dependency changes require review |

The script does not disable packet capture, raw sockets, wireless tools or IPv6; it does
not remove Kali packages, install Ubuntu repositories, or automatically start SSH.
It preserves an existing policy-rc.d and temporarily suppresses standard package-startup
hooks when no policy exists; selected services are explicitly activated afterward.

## Management IPs and lab listener ports

If you choose SSH/firewall, provide a narrow management allowlist such as
`192.0.2.25/32,2001:db8::25/128` (documentation examples; replace with real addresses).
The current remote SSH client must be included.

List additional **private listener ports** needed by an approved lab, such as `8443/tcp`,
to allow only management addresses. Public ports permit every source and should be
reserved for deliberately public services. Outbound connections remain permitted.
Existing active firewalls, Docker/containerd/libvirt, or routing cause firewall refusal.

If you depend on a VPN or container lab, leave this module off and keep your existing
workload-aware firewall policy. UFW does not provide complete Docker port protection.

## Rolling updates

Review the official [Kali update guidance](https://www.kali.org/docs/general-use/updating-a-package/):

```sh
sudo apt update
apt list --upgradable
sudo apt full-upgrade
```

Review proposed removals/dependency changes before accepting. Take a snapshot and reboot
during planned maintenance if required. This script never performs a full rolling upgrade.
Installing selected tools can still install/upgrade their dependencies.

It uses your configured APT repositories with normal signature verification and does not
replace sources.list or deb822 .sources files. Review the official [repository
documentation](https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/)
and avoid mixing Ubuntu/Debian release repositories into Kali.

## Post-apply lab checks

Before confirming, test login and sudo, VPN routing, proxy/tunnel operation, browser/Burp
workflows, capture permissions, wireless adapter availability and deliberately configured
listeners applicable to your own lab. Review journal/AppArmor denials if modules were
selected. Do not infer those tools work merely because the script finished.

Runtime execution on Kali has not been performed in the delivery session. The source
and mock tests are provided for review and disposable-VM validation before use.
