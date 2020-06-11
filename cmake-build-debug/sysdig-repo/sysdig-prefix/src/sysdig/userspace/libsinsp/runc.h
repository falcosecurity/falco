/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

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

#include <string>

class sinsp_threadinfo;

namespace libsinsp {
namespace runc {

/// runc-based runtimes (Docker, containerd, CRI-O, probably others) use the same two cgroup layouts
/// with slight variations:
/// - non-systemd layout uses cgroups ending with .../<prefix><container id>
/// - systemd layout uses .../<prefix><container id>.scope
/// where <container id> is always 64 hex digits (we report the first 12 as the container id).
/// For non-systemd only CRI-O seems to use /crio-<container id>, while for systemd layout
/// while all known container engines use a prefix like "docker-", "crio-" or "containerd-cri-".
/// We can encode all these variants with a simple list of (prefix, suffix) pairs
/// (the last one must be a pair of null pointers to mark the end of the array)
struct cgroup_layout {
	const char* prefix;
	const char* suffix;
};

/// If any of the cgroups of the thread in `tinfo` matches the `layout`, set `container_id` to the found id
/// and return true. Otherwise, return false and leave `container_id` unchanged
bool matches_runc_cgroups(const sinsp_threadinfo *tinfo, const cgroup_layout *layout, std::string &container_id);
}
}
