#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 The Falco Authors.
"""Execute package script templates without root, systemd, DKMS, or a network.

Only configure-time substitutions, filesystem prefixes, and RPM systemd macros
are replaced. Stateful command shims model external programs; the package's shell
control flow and file operations run unchanged. Real RPM macro expansion and
kernel-module loading also need package integration tests.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
OLD = "10.2.0+driver"
NEW = "11.0.0-rc1+driver"
PIN = "11.0.1+driver"
KERNEL = "6.8.0-test"

# Each shim persists observable external state across separate scriptlets.
SHIM = r'''
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["PACKAGE_TEST_ROOT"])
state_file = root / "state.json"
state = json.loads(state_file.read_text())
command = Path(sys.argv[0]).name
args = sys.argv[1:]
state["calls"].append([command, *args])
code = 0

def option(name):
    return args[args.index(name) + 1]

def unlink(path):
    if path.is_symlink() or path.exists():
        path.unlink()

def systemctl(action, units):
    global code
    alias = root / "etc/systemd/system/falco.service"
    mask = root / "etc/systemd/system/falcoctl-artifact-follow.service"
    if action == "mask":
        if not mask.is_symlink():
            mask.symlink_to("/dev/null")
    elif action == "unmask":
        unlink(mask)
    for unit in units:
        if action == "stop":
            state["active"][unit] = False
        elif action == "disable":
            # Removing the unit first prevents resolving its Alias= metadata.
            if (root / "usr/lib/systemd/system" / unit).exists():
                state["enabled"][unit] = False
                if alias.is_symlink() and alias.readlink().name == unit:
                    unlink(alias)
        elif action == "enable":
            state["enabled"][unit] = True
            unlink(alias)
            alias.symlink_to(root / "usr/lib/systemd/system" / unit)
        elif action == "start":
            ready = unit != "falco-kmod.service" or bool(state["module"])
            state["active"][unit] = ready
            code = 0 if ready else 1

if command == "falco":
    if state["json_config"] and ("-c" not in args or option("-c") != "/dev/null"
                                 or "-o" not in args or option("-o") != "json_output=false"):
        print("Configured Falco requires a configuration-independent version probe", file=sys.stderr)
        code = 1
    else:
        print("Default driver: " + state["default"])
elif command == "falcoctl":
    config_file = root / "etc/falcoctl/falcoctl.yaml"
    config = json.loads(config_file.read_text()) if config_file.exists() else {}
    if args[:2] == ["driver", "printenv"]:
        if not config_file.exists():
            config_file.write_text(json.dumps(config))
        version = os.environ.get("FALCOCTL_DRIVER_VERSION", config.get("version", ""))
        print('DRIVER_VERSION="' + version + '"')
        print('DRIVER="' + config.get("type", "kmod") + '"')
    elif args[:2] == ["driver", "config"]:
        config["version"] = option("--version")
        types = [args[i + 1] for i, arg in enumerate(args) if arg == "--type"]
        config["type"] = state["automatic_type"] if len(types) > 1 else types[0]
        config_file.write_text(json.dumps(config))
    elif args[:2] == ["driver", "install"]:
        state["installs"] += 1
        # The old cache path reports success after removing its DKMS module.
        state["module"] = "" if state["cache_hit"] else option("--version")
    elif args[:2] == ["driver", "cleanup"]:
        state["cleanups"] += 1
        state["module"] = ""
    else:
        raise RuntimeError(args)
elif command == "dkms":
    state["dkms_installs"] += 1
    code = 7 if state["dkms_failure"] else 0
    if code == 0:
        state["module"] = "wrong-version" if state["dkms_wrong_version"] else option("-v")
elif command == "modinfo":
    print(state["module"])
    code = 0 if state["module"] else 1
elif command == "uname":
    print("6.8.0-test")
elif command == "systemctl":
    args = [arg for arg in args if arg != "--system"]
    systemctl(args[0], args[1:])
elif command == "rpm-systemd-preun":
    # Model the final-removal guard in %systemd_preun, not an RPM installation.
    if args[0] == "0":
        systemctl("disable", args[1:])
elif command == "rpm-systemd-post":
    pass  # Presetting is separate from the scripts' explicit enable/start.
elif command != "clear":
    raise RuntimeError(command)
state_file.write_text(json.dumps(state))
sys.exit(code)
'''


class PackageHost:
    def __init__(self, case, package_format, version=OLD):
        self.case = case
        self.format = package_format
        temporary = tempfile.TemporaryDirectory(prefix="falco-package-test-")
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state_file = self.root / "state.json"
        self.config_file = self.root / "etc/falcoctl/falcoctl.yaml"
        self.package_state = self.root / "var/lib/falco/package"
        self.mask = self.root / "etc/systemd/system/falcoctl-artifact-follow.service"
        self.alias = self.root / "etc/systemd/system/falco.service"
        for directory in ("bin", "etc/falcoctl", "etc/systemd/system", "usr/lib/systemd/system"):
            (self.root / directory).mkdir(parents=True)
        for unit in ("kmod", "modern-bpf", "custom"):
            (self.root / f"usr/lib/systemd/system/falco-{unit}.service").touch()
        (self.root / "usr/lib/systemd/system/falcoctl-artifact-follow.service").touch()
        self.set_config(version)
        self.write_state({
            "default": OLD, "module": OLD, "cache_hit": True, "json_config": False,
            "automatic_type": "kmod", "dkms_failure": False,
            "dkms_wrong_version": False, "installs": 0, "cleanups": 0,
            "dkms_installs": 0, "calls": [], "enabled": {},
            "active": {"falco-kmod.service": True},
        })
        for command in ("falco", "falcoctl", "dkms", "modinfo", "uname", "systemctl",
                        "clear", "rpm-systemd-preun", "rpm-systemd-post"):
            path = self.root / "bin" / command
            path.write_text(f"#!{sys.executable}\n" + SHIM)
            path.chmod(0o755)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith("FALCO")}
        self.env.update({
            "PATH": str(self.root / "bin") + os.pathsep + os.defpath,
            "PACKAGE_TEST_ROOT": str(self.root),
            "FALCO_FRONTEND": "noninteractive", "FALCO_DRIVER_CHOICE": "kmod",
            "FALCOCTL_ENABLED": "yes",
        })

    def state(self):
        return json.loads(self.state_file.read_text())

    def write_state(self, value):
        self.state_file.write_text(json.dumps(value))

    def update(self, **values):
        self.write_state(dict(self.state(), **values))

    def set_config(self, version):
        self.config_file.write_text(json.dumps({
            "version": version, "type": "kmod", "artifact_customization": "preserve me",
        }))

    def config(self):
        return json.loads(self.config_file.read_text())

    def run(self, script, *args, success=True):
        functions = (SCRIPTS / "packaging/functions.sh.in").read_text()
        functions = functions.replace("@DRIVER_VERSION@", NEW)
        content = (SCRIPTS / self.format / f"{script}.in").read_text()
        content = content.replace("@FALCO_PACKAGE_FUNCTIONS@", functions)
        content = content.replace("@DRIVER_VERSION@", NEW)
        # One substitution pass avoids rewriting prefixes introduced by itself.
        content = re.sub(
            r"/(?:usr/lib/systemd/system|lib/systemd/system|etc/systemd/system|etc/falcoctl|var/lib/falco)",
            lambda match: str(self.root) + match[0], content,
        )
        content = re.sub(r"^%systemd_preun\b", 'rpm-systemd-preun "$1"', content, flags=re.M)
        content = re.sub(r"^\s*%systemd_post\b", '\nrpm-systemd-post "$1"', content, flags=re.M)
        self.case.assertNotRegex(content, r"@[A-Z_]+@", "unrendered CMake variable")
        path = self.root / script
        path.write_text(content)
        result = subprocess.run(["/bin/sh", str(path), *args], env=self.env,
                                text=True, capture_output=True)
        if success:
            self.case.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.case.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def preinstall(self):
        if self.format == "debian":
            self.run("preinst", "upgrade", "0.44.1")
        else:
            self.run("preinstall", "2")

    def postinstall(self, **kwargs):
        script, argument = ("postinst", "configure") if self.format == "debian" else ("postinstall", "2")
        return self.run(script, argument, **kwargs)

    def finish(self, **kwargs):
        if self.format == "rpm":
            return self.run("posttrans", "2", **kwargs)

    def assert_running(self, version):
        self.case.assertEqual(self.config()["version"], version)
        self.case.assertEqual(self.config()["artifact_customization"], "preserve me")
        self.case.assertEqual(self.state()["module"], version)
        self.case.assertTrue(self.state()["active"]["falco-kmod.service"])
        self.case.assertTrue(self.state()["enabled"]["falco-kmod.service"])
        self.case.assertEqual(list(self.package_state.glob("previous-*")), [])
        self.case.assertFalse((self.package_state / "pending-driver").exists())


class PackageScriptTests(unittest.TestCase):
    def test_upgrade_migrates_outgoing_default(self):
        for package_format in ("debian", "rpm"):
            with self.subTest(package_format=package_format):
                host = PackageHost(self, package_format)
                host.preinstall()
                if package_format == "rpm":
                    host.set_config(NEW)  # RPM has replaced the payload at %post.
                host.postinstall()
                host.finish()
                host.assert_running(NEW)

    def test_preserves_custom_pin_including_replaced_rpm_config(self):
        for package_format in ("debian", "rpm"):
            with self.subTest(package_format=package_format):
                host = PackageHost(self, package_format, version=PIN)
                host.preinstall()
                if package_format == "rpm":
                    host.set_config(NEW)
                host.postinstall()
                host.finish()
                host.assert_running(PIN)

    def test_explicit_environment_pin_overrides_default_migration(self):
        for package_format in ("debian", "rpm"):
            with self.subTest(package_format=package_format):
                host = PackageHost(self, package_format)
                host.preinstall()
                host.env["FALCOCTL_DRIVER_VERSION"] = OLD
                host.postinstall()
                host.finish()
                host.assert_running(OLD)

    def test_none_does_not_reconfigure_install_or_start(self):
        for package_format in ("debian", "rpm"):
            with self.subTest(package_format=package_format):
                host = PackageHost(self, package_format, version=PIN)
                host.env["FALCO_DRIVER_CHOICE"] = "none"
                host.preinstall()
                host.postinstall()
                host.finish()
                self.assertEqual(host.config()["version"], PIN)
                self.assertEqual(host.state()["installs"], 0)
                self.assertFalse(any(host.state()["active"].values()))

    def test_rpm_provisions_only_after_outgoing_cleanup(self):
        host = PackageHost(self, "rpm")
        host.preinstall()
        host.set_config(NEW)
        host.postinstall()
        self.assertEqual(host.state()["installs"], 0)
        self.assertFalse(any(host.state()["active"].values()))
        self.assertTrue((host.package_state / "pending-driver").exists())
        # Simulate an old package's unconditional %preun after the new %post.
        host.update(module="", active={})
        host.finish()
        host.assert_running(NEW)
        installs = host.state()["installs"]
        host.finish()  # A completed transaction cannot be replayed.
        self.assertEqual(host.state()["installs"], installs)

    def test_rpm_preun_upgrade_preserves_service_and_driver(self):
        host = PackageHost(self, "rpm")
        host.run("preuninstall", "1")
        self.assertEqual(host.state()["cleanups"], 0)
        self.assertEqual(host.state()["module"], OLD)
        self.assertTrue(host.state()["active"]["falco-kmod.service"])

    def test_kmod_cache_hit_repairs_dkms_but_compiled_driver_needs_no_repair(self):
        for package_format in ("debian", "rpm"):
            for cache_hit in (True, False):
                with self.subTest(package_format=package_format, cache_hit=cache_hit):
                    host = PackageHost(self, package_format, version=NEW)
                    host.update(cache_hit=cache_hit)
                    host.postinstall()
                    host.finish()
                    host.assert_running(NEW)
                    self.assertEqual(host.state()["dkms_installs"], int(cache_hit))

    def test_failed_or_wrong_dkms_install_retains_state_for_retry(self):
        for package_format in ("debian", "rpm"):
            for failure in ("dkms_failure", "dkms_wrong_version"):
                with self.subTest(package_format=package_format, failure=failure):
                    host = PackageHost(self, package_format)
                    host.preinstall()
                    if package_format == "rpm":
                        host.set_config(NEW)
                    host.update(**{failure: True})
                    host.postinstall(success=package_format == "rpm")
                    if package_format == "rpm":
                        host.finish(success=False)
                        self.assertTrue((host.package_state / "pending-driver").exists())
                    self.assertFalse(any(host.state()["active"].values()))
                    self.assertEqual((host.package_state / "previous-default").read_text().strip(), OLD)
                    self.assertEqual((host.package_state / "previous-version").read_text().strip(), OLD)
                    host.update(**{failure: False})
                    if package_format == "debian":
                        host.postinstall()  # dpkg --configure retries without unpack/preinst.
                    else:
                        host.finish()
                    host.assert_running(NEW)

    def test_old_falco_json_configuration_does_not_break_default_migration(self):
        for package_format in ("debian", "rpm"):
            with self.subTest(package_format=package_format):
                host = PackageHost(self, package_format)
                host.update(json_config=True)
                host.preinstall()
                self.assertEqual((host.package_state / "previous-default").read_text().strip(), OLD)
                if package_format == "rpm":
                    host.set_config(NEW)
                host.postinstall()
                host.finish()
                host.assert_running(NEW)

    def test_automatic_driver_selection_and_modern_bpf_skip_install(self):
        for package_format in ("debian", "rpm"):
            for driver in ("auto", "modern_ebpf"):
                with self.subTest(package_format=package_format, driver=driver):
                    host = PackageHost(self, package_format, version=NEW)
                    host.env["FALCO_DRIVER_CHOICE"] = driver
                    host.update(automatic_type="modern_ebpf")
                    host.postinstall()
                    host.finish()
                    self.assertEqual(host.state()["installs"], 0)
                    self.assertTrue(host.state()["active"]["falco-modern-bpf.service"])

    def test_removal_clears_only_package_owned_mask(self):
        for package_format in ("debian", "rpm"):
            for administrator_mask in (True, False):
                with self.subTest(package_format=package_format, administrator_mask=administrator_mask):
                    host = PackageHost(self, package_format, version=NEW)
                    host.env["FALCOCTL_ENABLED"] = "no"
                    if administrator_mask:
                        host.mask.symlink_to("/dev/null")
                    host.postinstall()
                    host.finish()
                    self.assertEqual((host.package_state / "follower-mask").exists(), not administrator_mask)
                    if package_format == "debian":
                        host.run("prerm", "remove")
                    else:
                        host.run("preuninstall", "0")
                    # Alias must be removed before deleting the packaged unit.
                    self.assertFalse(host.alias.is_symlink())
                    self.assertEqual(host.state()["module"], "")
                    self.assertFalse(any(host.state()["active"].values()))
                    for unit in (host.root / "usr/lib/systemd/system").iterdir():
                        unit.unlink()
                    if package_format == "debian":
                        host.run("postrm", "remove")
                        host.run("postrm", "purge")
                    else:
                        host.run("postuninstall", "0")
                    self.assertEqual(host.mask.is_symlink(), administrator_mask)

    def test_postrm_repairs_only_dangling_package_aliases(self):
        for target, live, retained in (("falco-kmod.service", False, False),
                                      ("falco-kmod.service", True, True),
                                      ("administrator.service", False, True)):
            with self.subTest(target=target, live=live):
                host = PackageHost(self, "debian")
                unit = host.root / "usr/lib/systemd/system" / target
                if not live and unit.exists():
                    unit.unlink()
                host.alias.symlink_to(unit)
                host.run("postrm", "purge")
                self.assertEqual(host.alias.is_symlink(), retained)

    def test_administrator_unit_replacing_owned_mask_survives_upgrade_and_removal(self):
        for package_format in ("debian", "rpm"):
            with self.subTest(package_format=package_format):
                host = PackageHost(self, package_format, version=NEW)
                host.env["FALCOCTL_ENABLED"] = "no"
                host.postinstall()
                host.finish()
                self.assertTrue((host.package_state / "follower-mask").exists())
                host.mask.unlink()
                custom_unit = "[Service]\nExecStart=/usr/local/bin/custom-follower\n"
                host.mask.write_text(custom_unit)
                host.env["FALCOCTL_ENABLED"] = "yes"
                host.postinstall()
                host.finish()
                self.assertEqual(host.mask.read_text(), custom_unit)
                self.assertFalse((host.package_state / "follower-mask").exists())
                if package_format == "debian":
                    host.run("prerm", "remove")
                    host.run("postrm", "purge")
                else:
                    host.run("preuninstall", "0")
                    host.run("postuninstall", "0")
                self.assertEqual(host.mask.read_text(), custom_unit)

    def test_fresh_preinstall_does_not_create_falcoctl_config(self):
        for package_format in ("debian", "rpm"):
            with self.subTest(package_format=package_format):
                host = PackageHost(self, package_format)
                host.config_file.unlink()
                host.update(default="")
                host.preinstall()
                self.assertFalse(host.config_file.exists())
                self.assertFalse(any(call[0] == "falcoctl" for call in host.state()["calls"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
