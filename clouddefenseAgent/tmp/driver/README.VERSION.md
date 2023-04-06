# API version number

The file API_VERSION must contain a semver-like version number of the userspace<->kernel API. All other lines are ignored.

## When to increment

**major version**: increment when the driver API becomes incompatible with previous userspace versions

**minor version**: increment when new features are added but existing features remain compatible

**patch version**: increment when code changes don't break compatibility (e.g. bug fixes)

Do *not* increment for patches that only add support for new kernels, without affecting already supported ones.

# Schema version number

The file SCHEMA_VERSION must contain a semver-like version number of the event schema. All other lines are ignored.

## When to increment

**major version**: increment when the schema becomes incompatible with previous userspace versions

**minor version**: increment when new features are added but existing features remain compatible (e.g. new event fields or new events)

**patch version**: increment when code changes don't break compatibility (e.g. bug fixes in filler code)
