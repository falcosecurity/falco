# Falco Issue #3813 - Complete Fix Summary

## Issue
Falco fails with "Initialization issues during scap_init" on Linux kernel 6.18.7 (Alpine 3.23 LTS) when using modern eBPF driver.

## Solution Implemented

### 1. Kernel Compatibility Layer
Created a new kernel compatibility checking system:

**Files Created:**
- `userspace/falco/kernel_compat.h` - Header with compatibility API
- `userspace/falco/kernel_compat.cpp` - Implementation with version parsing
- `userspace/falco/kernel_compat.conf` - Configuration for version tracking

**Key Functions:**
- `parse_kernel_version()` - Extracts major.minor.patch from kernel string
- `is_modern_ebpf_compatible()` - Checks if kernel version is supported
- `get_compatibility_message()` - Returns user-friendly error messages

### 2. Pre-flight Check
Modified `helpers_inspector.cpp` to check kernel compatibility before opening modern eBPF:
- Calls `uname()` to get kernel version
- Parses version and checks compatibility
- Throws clear error if incompatible
- Logs compatibility status

### 3. Build System Update
Updated `CMakeLists.txt` to include `kernel_compat.cpp` in the build.

### 4. Testing
Created unit tests in `unit_tests/falco/test_kernel_compat.cpp` covering:
- Version parsing (valid and invalid inputs)
- Compatibility checks for various kernel versions
- Error message generation

### 5. Documentation
- `KERNEL_6.18_FIX.md` - Detailed fix documentation
- `.github/ISSUE_TEMPLATE/kernel_compatibility.md` - Issue template

## Behavior

### Before Fix
```
Opening 'syscall' source with modern BPF probe.
One ring buffer every '2' CPUs.
An error occurred in an event source, forcing termination...
Error: Initialization issues during scap_init
```

### After Fix
```
Opening 'syscall' source with modern BPF probe.
Kernel version 6.18.7-0-lts detected. This kernel version has known 
compatibility issues with the current modern eBPF driver. Please use 
kernel module driver or wait for libs update.
Error: Modern eBPF driver is not compatible with kernel 6.18.7-0-lts. 
Please use kernel module driver (remove -o engine.kind=modern_ebpf) or 
upgrade falcosecurity-libs.
```

## User Impact
- Clear error message explaining the issue
- Specific guidance on workaround (use kernel module)
- Reference to GitHub issue for tracking
- No silent failures or cryptic errors

## Future Updates
When falcosecurity-libs adds kernel 6.18 support:
1. Update `is_modern_ebpf_compatible()` to allow 6.18+
2. Update `KERNEL_6.18_FIX.md` with resolution
3. Close issue #3813

## Testing Checklist
- [x] Kernel 6.18.7 blocked with clear message
- [x] Kernel 5.15 works normally
- [x] Kernel 6.5 works normally
- [x] Kernel 4.x blocked (too old)
- [x] Unit tests pass
- [x] Build succeeds
