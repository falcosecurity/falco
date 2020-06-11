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
	id = "procs_fd_usage",
	name = "Processes FD Usage",
	description = "This view summarizes file descriptor usage for the processes in the system.",
	tips = {
	"A process that reaches its FD limit will very likely be killed by the OS. As a consequence, processes for which the OPEN column value is close to the MAX column value (or which, alternatively, have a PCT value close to 100) deserve particular attention.",
	"Clicking enter on a selection will show the activity I/O activity done by the process on different families of FDs."},
	tags = {"Default"},
	view_type = "table",
	filter = "evt.type!=switch",
	applies_to = {"", "container.id", "fd.name", "fd.containername", "fd.sport", "fd.sproto", "evt.type", "fd.directory", "fd.containerdirectory", "fd.type", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	is_root = true,
	drilldown_target = "io_by_type",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
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
			name = "OPEN",
			field = "proc.fdopencount",
			description = "Number of open FDs that the process currently has. On a trace file, this is the maximum value reached by the process over the whole file.",
			aggregation = "MAX",
			colsize = 8,
			is_sorting = true,
		},
		{
			name = "MAX",
			field = "proc.fdlimit",
			description = "Maximum number of FDs that this process can open.",
			aggregation = "MAX",
			colsize = 8,
		},
		{
			name = "PCT",
			field = "proc.fdusage",
			description = "Percentage of currently open FDs versus the maximum allows for this process. In other words, this euquals to OPEN * 100 / MAX, and can be used to quickly identify processes that are getting close to their limit.",
			aggregation = "MAX",
			colsize = 8,
		},
		{
			tags = {"containers"},
			name = "The container this process belongs to.",
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
