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
	id = "io_by_type",
	name = "I/O by Type",
	description = "Show an overview of the I/O volume based on I/O type. Possible I/O types are: file, directory, ipv4 or ipv6 network traffic, pipe, unix socket, signal fd, event fd, inotify fd.",
	tips = {"This view is a good starting point to understand what a machine is doing besides CPU computation. Remeber that you can apply it to a process or to a container as well, to get an overview of what they are doing."},
	tags = {"Default", "wsysdig"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "thread.nametid", "proc.name", "thread.tid", "fd.sport", "fd.sproto", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	use_defaults = true,
	drilldown_target = "procs",
	columns = 
	{
		{
			name = "NA",
			field = "fd.type",
			is_key = true
		},
		{
			name = "BPS IN",
			field = "evt.buflen.in",
			description = "Bytes per second read from the FDs of the specific type.",
			colsize = 12,
			aggregation = "TIME_AVG"
		},
		{
			name = "BPS OUT",
			field = "evt.buflen.out",
			description = "Bytes per second written to the FDs of the specific type.",
			colsize = 12,
			aggregation = "TIME_AVG"
		},
		{
			is_sorting = true,
			name = "IOPS",
			field = "evt.count",
			description = "Number of I/O operations for the specified I/O category. This counts all the operations on the file, including, open, close, read, write, stat, and so on. As a consequence, this value can be nonzero even if I/O bytes for the file are zero.",
			colsize = 9,
			aggregation = "TIME_AVG"
		},
		{
			name = "TIME",
			field = "evt.latency",
			description = "Time spent by processes doing any I/O operation (including wait) of this type.",
			colsize = 9,
			aggregation = "SUM"
		},
		{
			name = "I/O Type",
			field = "fd.type",
			description = "Type of I/O. Can be one of: file, directory, ipv4, ipv6, pipe, unix, signal, event, inotify",
			aggregation = "SUM",
			colsize = 0
		},
	}
}
