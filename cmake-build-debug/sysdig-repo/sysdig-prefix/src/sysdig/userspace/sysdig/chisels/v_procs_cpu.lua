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
	id = "procs_cpu",
	name = "Processes CPU",
	description = "Show total versus user versus system CPU usage for every process.",
	tips = {
		"A high value for both SYS and SYSCALLS likely means that the process is I/O bound. A high value for SYS and a moderate value for SYSCALLS might on the other side indicate a kernel bottleneck. In both cases, drilling down with the 'System Calls' view can help understand what's happening."
	},
	tags = {"Default", "wsysdig"},
	view_type = "table",
	filter = "evt.type!=switch",
	applies_to = {"", "container.id", "fd.name", "fd.containername", "fd.sport", "fd.sproto", "evt.type", "fd.directory", "fd.containerdirectory", "fd.type", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	is_root = true,
	drilldown_target = "threads",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "thread.tid",
			is_key = true
		},
		{
			name = "NA",
			field = "proc.pid",
			is_groupby_key = true
		},
		{
			name = "PID",
			description = "Process PID.",
			field = "proc.pid",
			colsize = 8,
		},
		{
			tags = {"containers"},
			name = "VPID",
			field = "proc.vpid",
			description = "PID that the process has inside the container.",
			colsize = 8,
		},
		{
			name = "TOT",
			field = "thread.cpu",
			description = "Total amount of CPU used by the proccess (user + system).",
			aggregation = "AVG",
			groupby_aggregation = "SUM",
			colsize = 8,
			is_sorting = true
		},
		{
			name = "USER",
			field = "thread.cpu.user",
			description = "Amount of user CPU used by the proccess.",
			aggregation = "AVG",
			groupby_aggregation = "SUM",
			colsize = 8,
		},
		{
			name = "SYS",
			field = "thread.cpu.system",
			description = "Amount of system CPU used by the proccess.",
			aggregation = "AVG",
			groupby_aggregation = "SUM",
			colsize = 8,
		},
		{
			name = "SYSCALLS",
			field = "evt.count",
			description = "Number of system calls per second made by the proccess.",
			aggregation = "TIME_AVG",
			groupby_aggregation = "SUM",
			colsize = 9,
		},
		{
			tags = {"containers"},
			name = "CONTAINER",
			description = "The container this process belongs to.",
			field = "container.name",
			colsize = 20
		},
		{
			name = "Command",
			description = "The full command line of the process.",
			field = "proc.exeline",
			aggregation = "MAX",
			colsize = 0
		}
	},
	actions = 
	{
		{
			hotkey = "9",
			command = "kill -9 %proc.pid",
			description = "kill -9",
			ask_confirmation = true,
			wait_finish = false
		},
		{
			hotkey = "c",
			command = "gcore %proc.pid",
			description = "generate core",
		},
		{
			hotkey = "g",
			command = "gdb -p %proc.pid",
			description = "gdb attach",
			wait_finish = false
		},
		{
			hotkey = "k",
			command = "kill %proc.pid",
			description = "kill",
			ask_confirmation = true,
			wait_finish = false
		},
		{
			hotkey = "l",
			command = "ltrace -p %proc.pid",
			description = "ltrace",
		},
		{
			hotkey = "s",
			command = "gdb -p %proc.pid --batch --quiet -ex \"thread apply all bt full\" -ex \"quit\"",
			description = "print stack",
		},
	},
}
