# Package lifecycle tests

Run the [script tests](test_package_scripts.py) with `python3 scripts/packaging/test_package_scripts.py`.
They execute the maintainer scripts with isolated files and command shims. Real
DEB/RPM transactions are also needed to validate package-manager ordering,
systemd aliases, DKMS, and startup after reboot.

The [shared helpers](functions.sh.in) are embedded at CMake configure time, so
removal scripts remain usable after the package files have been deleted.
RPM installation and startup run in `posttrans`, after outgoing packages have
finished their cleanup. Generating RPMs requires CMake 3.18 or newer.

On upgrade, a driver version matching the outgoing binary's default follows
the incoming package's default. Other pins are retained. A deliberate pin equal
to the outgoing default is indistinguishable from the package-generated value:
set `FALCOCTL_DRIVER_VERSION` explicitly during the transaction to retain it.
`FALCO_DRIVER_CHOICE=none` skips driver configuration and installation. Custom
pins still need compatible drivers and sources when selecting `kmod`.

The kmod package path verifies that `modprobe` can find the selected version.
With older bundled falcoctl releases, it repairs a missing installation through
DKMS. A failed repair stops the script before service startup and retains its
transaction state. This fallback uses the system's default DKMS compiler selection.

Only follower masks recorded as package-created are removed. Administrator
masks and older masks without ownership records are retained. Debian disables
units before removing their definitions and repairs known dangling Falco aliases
on removal or purge.

Non-interactive installs can preseed every prompt with environment variables,
on both DEB and RPM. `FALCO_FRONTEND=noninteractive` skips the `dialog`
prompts and keeps the defaults: automatic driver selection with ruleset
updates followed. `FALCO_DRIVER_CHOICE` preselects the driver menu with
`none` (no driver configuration, no unit started), `kmod`, or `modern_ebpf`;
any other value keeps automatic selection. `FALCOCTL_ENABLED=no` declines
the automatic ruleset updates prompt and masks
`falcoctl-artifact-follow.service`. Note that `FALCO_DRIVER_CHOICE=none`
also skips the ruleset updates prompt, since no driver is configured.
