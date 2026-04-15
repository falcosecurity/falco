// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <ctime>
#include <cstring>

// Portable gmtime_r: Windows provides gmtime_s with reversed arg order.
inline struct tm* falco_gmtime_r(const time_t* timer, struct tm* buf) {
#ifdef _WIN32
	return gmtime_s(buf, timer) == 0 ? buf : nullptr;
#else
	return gmtime_r(timer, buf);
#endif
}

// Portable localtime_r: Windows provides localtime_s with reversed arg order.
inline struct tm* falco_localtime_r(const time_t* timer, struct tm* buf) {
#ifdef _WIN32
	return localtime_s(buf, timer) == 0 ? buf : nullptr;
#else
	return localtime_r(timer, buf);
#endif
}

// Portable strerror_r: returns const char* on all platforms.
//
// - glibc with _GNU_SOURCE: returns char* that may point to buf or a static string
// - musl/macOS/WASM (XSI): returns int, always writes to buf
// - Windows: no strerror_r, uses strerror_s instead
//
// We check __GLIBC__ (not _GNU_SOURCE alone) because musl defines _GNU_SOURCE
// but always provides the XSI variant.
inline const char* falco_strerror_r(int errnum, char* buf, size_t len) {
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
	return strerror_r(errnum, buf, len);
#elif defined(_WIN32)
	strerror_s(buf, len, errnum);
	return buf;
#else
	strerror_r(errnum, buf, len);
	return buf;
#endif
}
