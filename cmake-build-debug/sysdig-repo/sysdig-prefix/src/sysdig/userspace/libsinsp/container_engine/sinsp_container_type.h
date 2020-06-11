/*
Copyright (C) 2019 Draios Inc dba Sysdig.

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

enum sinsp_container_type
{
	CT_DOCKER = 0,
	CT_LXC = 1,
	CT_LIBVIRT_LXC = 2,
	CT_MESOS = 3,
	CT_RKT = 4,
	CT_CUSTOM = 5,
	CT_CRI = 6,
	CT_CONTAINERD = 7,
	CT_CRIO = 8,
	CT_BPM = 9,
};
