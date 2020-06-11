#include <linux/version.h>

/**
 * for RHEL kernels, export the release code (which is equal to e.g.
 * RHEL_RELEASE_CODE(8, 1)) under our own name.
 * For other kernels, just use zeros.
 *
 * We need macros that are always defined to use in preprocessor directives
 * to express the required kernel version in a single expression, without
 * a multiline #ifdef soup.
 */
#ifdef RHEL_RELEASE_CODE
#define PPM_RHEL_RELEASE_CODE RHEL_RELEASE_CODE
#define PPM_RHEL_RELEASE_VERSION(x,y) RHEL_RELEASE_VERSION(x,y)
#else
#define PPM_RHEL_RELEASE_CODE 0
#define PPM_RHEL_RELEASE_VERSION(x,y) 0
#endif
