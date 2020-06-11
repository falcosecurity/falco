/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once
//
// This flag can be used to include unsupported or unrecognized sockets
// in the fd tables. It's useful to debug close() leaks
//
#define INCLUDE_UNKNOWN_SOCKET_FDS

//
// Memory storage size for an entry in the event storage LIFO.
// Events bigger than SP_EVT_BUF_SIZE won't be be stored in the LIFO.
//
#define SP_EVT_BUF_SIZE 4096

//
// If defined, the filtering system is compiled
//
#define HAS_FILTERING
#define HAS_CAPTURE_FILTERING

//
// Controls if assertions break execution or if they are just printed to the
// log
//
#define ASSERT_TO_LOG

//
// Controls if the library collects internal performance stats.
//
#undef GATHER_INTERNAL_STATS

//
// Read timeout specified when doing scap_open
//
#define SCAP_TIMEOUT_MS 30

//
// Max size that the thread table can reach
//
#define MAX_THREAD_TABLE_SIZE 131072
#define DEFAULT_THREAD_TABLE_SIZE 65536

//
// Max size that the FD table of a process can reach
//
#define MAX_FD_TABLE_SIZE 4096

//
// The time after an inactive thread is removed.
//
#define DEFAULT_THREAD_TIMEOUT_S 1800

//
// How often the thread table is scanned for inactive threads
//
#define DEFAULT_INACTIVE_THREAD_SCAN_TIME_S 1200

//
// How often the container table is scanned for inactive containers
//
#define DEFAULT_INACTIVE_CONTAINER_SCAN_TIME_S 30

//
// Enables Lua chisel scripts support
//
#define HAS_CHISELS

//
// Relative path to chisels
//
#define CHISELS_INSTALLATION_DIR "/share/sysdig/chisels"

//
// Default snaplen
//
#define DEFAULT_SNAPLEN 80

//
// Maximum user event buffer size
//
#define MAX_USER_EVT_BUFFER 65536

//
// Size the user event buffer is brought back once in a while 
//
#define MIN_USER_EVT_BUFFER 256
 
//
// Is csysdig functionality included?
//
#define CSYSDIG

#ifdef _WIN32
#define NOCURSESUI
#endif

//
// Name of the device used for tracer injection
//
#define USER_EVT_DEVICE_NAME "/dev/null"

//
// The time after which a clone should be considered stale
//
#define CLONE_STALE_TIME_NS 2000000000

//
// Port range to enable larger snaplen on
//
#define DEFAULT_INCREASE_SNAPLEN_PORT_RANGE {0, 0}

//
// FD class customized with the storage we need
//
#ifdef HAS_ANALYZER
#include "analyzer_settings.h"
#else
template<class T> class sinsp_fdinfo;
typedef sinsp_fdinfo<int> sinsp_fdinfo_t;
#endif // HAS_ANALYZER

// Max JSON we can parse from docker API or others
// Added because older docker versions have a bug that causes
// very big JSONs returned by container inspect call
static const unsigned MAX_JSON_SIZE_B = 500 * 1024; // 500 kiB

