import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import os
import json

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class HardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = [load("harden"), load("kali-hardening")]

    def test_network_validation_and_remote_client_membership(self):
        for module in self.modules:
            ranges = module.networks("192.0.2.10,2001:db8::/64")
            self.assertTrue(module.contains("192.0.2.10", ranges))
            self.assertFalse(module.contains("192.0.2.11", ranges))
            self.assertTrue(module.contains("2001:db8::12", ranges))
            for bad in ("", "0.0.0.0/0", "::/0", "192.0.2.1;reboot", "$(id)", "999.0.0.1"):
                with self.assertRaises(ValueError):
                    module.networks(bad)

    def test_port_inputs_reject_injection_and_invalid_ranges(self):
        for module in self.modules:
            self.assertEqual(module.ports("443/tcp,53/udp"), [(53, "udp"), (443, "tcp")])
            for bad in ("0/tcp", "65536/tcp", "22/tcp;reboot", "20:30/tcp", "53/icmp"):
                with self.assertRaises(ValueError):
                    module.ports(bad)

    def test_kali_never_renders_unattended_update_policy(self):
        kali = self.modules[1]
        with self.assertRaises(ValueError):
            kali.render({"updates": True}, {"ID": "kali"})

    def test_key_only_requires_explicit_selection_and_keeps_ssh_port(self):
        for module in self.modules:
            profile = {key: False for key in ("sysctl", "logging", "updates", "fail2ban", "audit")}
            profile.update(ssh=True, users=["labadmin"], key_only=False, forwarding=True)
            config = module.render(profile, {"ID": "debian"})[module.PATHS[1]]
            self.assertNotIn("PasswordAuthentication no", config)
            self.assertNotIn("Port ", config)
            self.assertIn("PermitRootLogin no", config)
            profile["key_only"] = True
            config = module.render(profile, {"ID": "debian"})[module.PATHS[1]]
            self.assertIn("AuthenticationMethods publickey", config)
            self.assertIn("KbdInteractiveAuthentication no", config)

    def test_atomic_write_refuses_symlink_without_touching_destination(self):
        for module in self.modules:
            with tempfile.TemporaryDirectory() as temp:
                original = Path(temp) / "original"
                original.write_text("keep")
                link = Path(temp) / "link"
                link.symlink_to(original)
                with self.assertRaises(RuntimeError):
                    module.write(str(link), "replace")
                self.assertEqual(original.read_text(), "keep")

    def test_restore_preserves_old_files_and_removes_new_files(self):
        for module in self.modules:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                state = root / "run-test"
                state.mkdir()
                first, second = root / "existing", root / "new"
                first.write_text("modified")
                second.write_text("new config")
                (state / "0").write_text("original")
                (state / "0").chmod(0o640)
                profile = {key: False for key in ("firewall", "ssh", "audit", "logging", "fail2ban", "apparmor", "updates")}
                manifest = {"originals": {str(first): True, str(second): False},
                            "sysctl": {}, "profile": profile, "services": {}}
                (state / "manifest.json").write_text(json.dumps(manifest))
                with patch.object(module, "PATHS", [str(first), str(second)]), \
                     patch.object(module, "secure_state", return_value=state), \
                     patch.object(module, "run"):
                    module.restore(state)
                self.assertEqual(first.read_text(), "original")
                self.assertEqual(first.stat().st_mode & 0o777, 0o640)
                self.assertFalse(second.exists())

    def test_restore_rejects_paths_outside_private_state_directory(self):
        for module in self.modules:
            for bad in ("/tmp/run-test", "/etc", "/var/lib/linux-hardening/../run-test"):
                with self.assertRaises(ValueError):
                    module.secure_state(bad)

if __name__ == "__main__":
    unittest.main()
