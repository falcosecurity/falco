---
name: Kernel Compatibility Issue
about: Report issues with specific kernel versions
title: '[KERNEL] Modern eBPF failure on kernel X.Y.Z'
labels: kind/bug, area/driver
---

## Kernel Information
- Kernel Version: (output of `uname -r`)
- Distribution: (e.g., Alpine 3.23, Ubuntu 22.04)
- Architecture: (e.g., x86_64, arm64)

## Falco Information
- Falco Version: (output of `falco --version`)
- Driver Type: (modern_ebpf, kmod, ebpf)
- Installation Method: (Docker, binary, package)

## Issue Description
Describe what happens when trying to start Falco.

## Error Output
```
Paste the full error output here
```

## Kernel Configuration
Please provide output of:
```bash
# Check BPF support
grep CONFIG_BPF /boot/config-$(uname -r)

# Check BTF availability
ls -lh /sys/kernel/btf/vmlinux
```

## Expected Behavior
What should happen?

## Workaround
Have you tried using the kernel module driver instead?
```bash
falco  # without -o 'engine.kind=modern_ebpf'
```
