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
	id = "slow_io",
	name = "Slow File I/O",
	description = "Lists all of the file read and write calls that took more than 1ms to complete, sorted based on completion time.",
	tags = {"Default", "wsysdig"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "thread.nametid", "thread.tid", "proc.name", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "evt.is_io=true and fd.type=file and (not fd.name contains '/dev/') and evt.latency>1000000",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "evt.rawtime",
			is_key = true
		},
		{
			name = "TIME",
			field = "evt.time",
			description = "Time when the command was executed.",
			colsize = 12,
		},
		{
			name = "LATENCY",
			field = "evt.latency",
			description = "The slow file name.",
			is_sorting = true,
			colsize = 8,
		},
		{
			name = "FILENAME",
			field = "fd.name",
			description = "The slow file name.",
			colsize = 32,
		},
		{
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			description = "Name of the container. What this field contains depends on the containerization technology. For example, for docker this is the content of the 'NAMES' column in 'docker ps'",
			colsize = 20
		},
		{
			name = "PID",
			field = "proc.pid",
			description = "PID of the process performing the I/O call.",
			colsize = 12,
		},
		{
			name = "Command",
			field = "proc.exeline",
			aggregation = "MAX",
			description = "The command accessing the slow file, including arguments.",
			colsize = 0
		}		
	}
}
