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
	id = "syscall_procs",
	name = "Syscall Callers",
	description = "Show the top processes based on number of system call invocations and time spent calling them.",
	tags = {"Default"},
	view_type = "table",
	applies_to = {"evt.type"},
	use_defaults = true,
	filter = "syscall.type exists",
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
		},
		{
			is_sorting = true,
			name = "CALLS/S",
			field = "evt.count",
			description = "Number of system calls per second that this process has invoked.",
			colsize = 10,
			aggregation = "TIME_AVG"
		},
		{
			name = "TIME",
			field = "evt.latency",
			description = "Total time spent on system calls by the process during the sample interval. On trace files, this is the total for the whole file.",
			colsize = 10,
			aggregation = "SUM"
		},
		{
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			description = "Name of the container. What this field contains depends on the containerization technology. For example, for docker this is the content of the 'NAMES' column in 'docker ps'",
			colsize = 20
		},
		{
			name = "Command",
			description = "The full command line of the process.",
			field = "proc.exeline",
			aggregation = "MAX",
			colsize = 0
		}
	}
}
