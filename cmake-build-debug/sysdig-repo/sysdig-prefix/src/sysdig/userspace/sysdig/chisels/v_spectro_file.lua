--[[
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

--]]
view_info = 
{
	id = "spectro_file",
	name = "Spectrogram-File",
	description = "File I/O latency spectrogram.",
	view_type = "spectrogram",
	applies_to = {"", "container.id", "proc.pid", "thread.nametid", "thread.tid", "proc.name", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name", "fd.name", "fd.containername", "fd.directory", "fd.containerdirectory", "fd.containerdirectory"},
	filter = "evt.dir=< and fd.type=file",
	use_defaults = false,
	columns = 
	{
		{
			name = "NA",
			field = "evt.latency.quantized",
			is_key = true
		},
		{
			name = "LATENCY",
			description = "file latency.",
			field = "evt.latency.quantized",
		},
		{
			name = "COUNT",
			description = "XXX.",
			field = "evt.count",
			aggregation = "SUM",
			colsize = 8,
		}
	}
}
