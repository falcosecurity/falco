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
	id = "syscalls",
	name = "System Calls",
	description = "Show the top system calls in the system based on number of invocations and time spent calling them.",
	tips = {
		"This view is useful to spot not only system activity saturation, but also things like high wait time.", 
		"Drill down by clicking enter on a system call to see which processes are using it.",
		"The AVG TIME column is useful to identify system operations that tend to be consistently slow and can be the cause of bottlenecks."},
	tags = {"Default", "wsysdig"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "thread.nametid", "proc.name", "thread.tid", "fd.sport", "fd.sproto", "fd.name", "fd.containername", "fd.directory", "fd.containerdirectory", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	use_defaults = true,
	filter = "syscall.type exists",
	drilldown_target = "syscall_procs",
	columns = 
	{
		{
			name = "NA",
			field = "evt.type",
			is_key = true
		},
		{
			is_sorting = true,
			name = "CALLS/S",
			field = "evt.count",
			description = "Number of calls per second for this system call.",
			colsize = 10,
			aggregation = "TIME_AVG"
		},
		{
			name = "TOT TIME",
			field = "evt.latency",
			description = "Total time spent waiting for the given system call to return.",
			colsize = 10,
			aggregation = "SUM"
		},
		{
			name = "AVG TIME",
			field = "evt.latency",
			description = "Average time spent in the given system call. This is calculated dividing the value under TOT TIME by the value under COUNT.",
			colsize = 10,
			aggregation = "AVG"
		},
		{
			name = "SYSCALL",
			field = "evt.type",
			description = "System call name.",
			colsize = 32,
			aggregation = "SUM"
		},
	}
}
