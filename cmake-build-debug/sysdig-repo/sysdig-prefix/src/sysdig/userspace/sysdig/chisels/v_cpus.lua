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

view_infoz = 
{
	id = "cores",
	name = "CPUs",
	description = "This is the typical top/htop process list, showing usage of resources like CPU, memory, disk and network on a by process basis.",
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "thread.nametid", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	is_root = true,
	use_defaults = true,
	drilldown_target = "procs",
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
		},
		{
			name = "NA",
			field = "evt.cpu",
			is_groupby_key = true
		},
		{
			name = "CORE",
			description = "CPU or Core ID.",
			field = "evt.cpu",
			colsize = 8,
		},
		{
			name = "CPU",
			field = "proc.cpu",
			description = "CPU usage.",
			colsize = 8,
			aggregation = "AVG",
			groupby_aggregation = "SUM",
			is_sorting = true
		},
		{
			name = "TH",
			field = "proc.nthreads",
			description = "Number of threads that the process contains.",
			aggregation = "MAX",
			groupby_aggregation = "SUM",
			colsize = 5
		}
	}
}
