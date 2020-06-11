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
	id = "page_faults",
	name = "Page Faults",
	description = "This view shows page fault counters for processes. Both minor and major page faults are reported for each process. The counters report the number of page faults since process start.",
	tips = {
		"Major page faults are typically the ones you really want to keep an eye on. They are the ones causing pages swapping to disk, thus dramatically slowing down process execution.",
		"When applying this view on a live system, if the system is well tuned for performance you should see no changes in the first column."
	},
	tags = {"Default", "wsysdig"},
	view_type = "table",
	filter = "evt.type!=switch",
	applies_to = {"", "container.id", "fd.name", "fd.containername", "fd.sport", "fd.sproto", "evt.type", "fd.directory", "fd.containerdirectory", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	drilldown_target = "errors",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
		},
		{
			name = "MAJOR",
			field = "thread.pfmajor",
			description = "Number of major page faults that the process generated since its start.",
			colsize = 9,
			aggregation = "MAX",
			is_sorting = true
		},
		{
			name = "MINOR",
			field = "thread.pfminor",
			description = "Number of minor page faults that the process generated since its start.",
			colsize = 9,
			aggregation = "MAX"
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
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			description = "Name of the container. What this field contains depends on the containerization technology. For example, for docker this is the content of the 'NAMES' column in 'docker ps'",
			colsize = 20
		},
		{
			name = "Command",
			description = "Full command line of the process.",
			field = "proc.exeline",
			aggregation = "MAX",
			colsize = 0
		}
	}
}
