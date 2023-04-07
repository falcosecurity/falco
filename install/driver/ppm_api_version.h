#ifndef PPM_API_VERSION_H
#define PPM_API_VERSION_H

/*
 * API version component macros
 *
 * The version is a single uint64_t, structured as follows:
 * bit 63: unused (so the version number is always positive)
 * bits 44-62: major version
 * bits 24-43: minor version
 * bits 0-23: patch version
 */

#define PPM_VERSION_PACK(val, bits, shift) ((((unsigned long long)(val)) & ((1ULL << (bits)) - 1)) << (shift))
#define PPM_VERSION_UNPACK(val, bits, shift) ((((unsigned long long)(val)) >> (shift)) & ((1ULL << (bits)) - 1))

/* extract components from an API version number */
#define PPM_API_VERSION_MAJOR(ver) PPM_VERSION_UNPACK(ver, 19, 44)
#define PPM_API_VERSION_MINOR(ver) PPM_VERSION_UNPACK(ver, 20, 24)
#define PPM_API_VERSION_PATCH(ver) PPM_VERSION_UNPACK(ver, 24, 0)

/* build an API version number from components */
#define PPM_API_VERSION(major, minor, patch) \
	PPM_VERSION_PACK(major, 19, 44) | \
	PPM_VERSION_PACK(minor, 20, 24) | \
	PPM_VERSION_PACK(patch, 24, 0)

#define PPM_API_CURRENT_VERSION PPM_API_VERSION( \
	PPM_API_CURRENT_VERSION_MAJOR, \
	PPM_API_CURRENT_VERSION_MINOR, \
	PPM_API_CURRENT_VERSION_PATCH)

#define PPM_SCHEMA_CURRENT_VERSION PPM_API_VERSION( \
	PPM_SCHEMA_CURRENT_VERSION_MAJOR, \
	PPM_SCHEMA_CURRENT_VERSION_MINOR, \
	PPM_SCHEMA_CURRENT_VERSION_PATCH)

#define __PPM_STRINGIFY1(x) #x
#define __PPM_STRINGIFY(x) __PPM_STRINGIFY1(x)

#define PPM_API_CURRENT_VERSION_STRING \
	__PPM_STRINGIFY(PPM_API_CURRENT_VERSION_MAJOR) "." \
	__PPM_STRINGIFY(PPM_API_CURRENT_VERSION_MINOR) "." \
	__PPM_STRINGIFY(PPM_API_CURRENT_VERSION_PATCH)

#define PPM_SCHEMA_CURRENT_VERSION_STRING \
	__PPM_STRINGIFY(PPM_SCHEMA_CURRENT_VERSION_MAJOR) "." \
	__PPM_STRINGIFY(PPM_SCHEMA_CURRENT_VERSION_MINOR) "." \
	__PPM_STRINGIFY(PPM_SCHEMA_CURRENT_VERSION_PATCH)

#endif
