/*

Copyright (C) 2022 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#pragma once

/* taken from driver/API_VERSION */
#define PPM_API_CURRENT_VERSION_MAJOR 4
#define PPM_API_CURRENT_VERSION_MINOR 0
#define PPM_API_CURRENT_VERSION_PATCH 0

/* taken from driver/SCHEMA_VERSION */
#define PPM_SCHEMA_CURRENT_VERSION_MAJOR 2
#define PPM_SCHEMA_CURRENT_VERSION_MINOR 3
#define PPM_SCHEMA_CURRENT_VERSION_PATCH 0

#include "ppm_api_version.h"

#define DRIVER_VERSION "6c11056815b9eff787c69f9b2188a2ae503533c9"

#define DRIVER_NAME "falco"

#define DRIVER_DEVICE_NAME "falco"

#define DRIVER_COMMIT "e10d54df39201fc9ea524b461495d4eeb58df4e8"

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME DRIVER_NAME
#endif
