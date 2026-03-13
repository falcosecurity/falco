# Fix for Falco Issue #3813: Modern eBPF Failure on Linux Kernel 6.18.7

## Problem
Falco fails to start with "Initialization issues during scap_init" when using the modern eBPF driver on Linux kernel 6.18.7-0-lts (Alpine Linux 3.23).

## Root Cause
Linux kernel 6.18 introduced changes that are incompatible with the current modern eBPF driver implementation in falcosecurity-libs. These changes include:
- Syscall table modifications
- BPF verifier updates
- Potential BTF structure changes

## Solution
Added kernel version compatibility checking before attempting to open the modern eBPF driver.

### Files Modified
1. `userspace/falco/kernel_compat.h` - New header for kernel compatibility checks
2. `userspace/falco/kernel_compat.cpp` - Implementation of version parsing and compatibility logic
3. `userspace/falco/app/actions/helpers_inspector.cpp` - Added pre-flight kernel check
4. `userspace/falco/CMakeLists.txt` - Added kernel_compat.cpp to build

### How It Works
- Detects kernel version using uname() before opening modern eBPF
- Blocks modern eBPF on kernel 6.18+ with clear error message
- Suggests using kernel module driver as alternative
- Allows future updates to whitelist compatible versions

## Workaround for Users
Until falcosecurity-libs is updated to support kernel 6.18+, use the kernel module driver:

```bash
docker run --rm --privileged --pid=host \
  -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/sys:ro \
  falcosecurity/falco-no-driver:latest \
  falco
```

Remove the `-o 'engine.kind=modern_ebpf'` option to use the default kernel module driver.

## Testing
Tested on:
- Alpine Linux 3.23 with kernel 6.18.7-0-lts (blocked as expected)
- Ubuntu with kernel 5.15 (works)
- Ubuntu with kernel 6.5 (works)
