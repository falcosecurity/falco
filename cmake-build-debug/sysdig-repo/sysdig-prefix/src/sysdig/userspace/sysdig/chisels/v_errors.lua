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
	id = "errors",
	name = "Errors",
	description = "This view shows the top system call errors, sorted by number of occurrences. Errors are shows as errno codes. Do a 'man errno' to find the meaning of the most important codes.",
	tips = {
		"This view can be applied not only to the whole machine, but also to single processes, containers, threads and so on. Use it after a drill down for more fine grained investigation.",
		"Drill down on an error by clicking enter to see which processes are generating it."
	},
	tags = {"Default", "wsysdig"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "thread.nametid", "proc.name", "thread.tid", "fd.sport", "fd.sproto", "fd.directory", "fd.containerdirectory", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "evt.res != SUCCESS",
	use_defaults = true,
	drilldown_target = "procs_errors",
	columns = 
	{
		{
			name = "NA",
			field = "evt.res",
			is_key = true
		},
		{
			name = "COUNT",
			field = "evt.count",
			description = "The number of times the error happened during the sample interval. On trace files, this is the total for the whole file.",
			colsize = 12,
			aggregation = "SUM",
			is_sorting = true,
		},
		{
			name = "ERROR",
			description = "The error 'errno' code. Do a 'man errno' to find the meaning of the most important codes.",
			field = "evt.res",
			colsize = 0
		}
	}
}
