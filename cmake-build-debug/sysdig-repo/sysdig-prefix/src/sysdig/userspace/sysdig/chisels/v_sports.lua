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
	id = "sports",
	name = "Server Ports",
	description = "This view lists all of the server ports in terms of network bandwidth usage.",
	tips = {"Want to restrict this visualization to a single process or container? Just drill down into them before applying it.", 
		"Select a port and drill down with the 'Top Processes' view to see which processes are generating traffic on a port."},
	tags = {"wsysdig"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "thread.nametid", "thread.tid", "proc.name", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "(fd.type=ipv4 or fd.type=ipv6) and fd.name!=''",
	use_defaults = true,
	drilldown_target = "connections",
	columns = 
	{
		{
			name = "NA",
			field = "fd.sport",
			is_key = true
		},
		{
			name = "SPORT",
			description = "Server Port.",
			field = "fd.sport",
			colsize = 8,
		},
		{
			name = "BPS IN",
			field = "evt.buflen.net.in",
			description = "This port's input bandwidth in bytes per second.",
			is_sorting = true,
			colsize = 12,
			aggregation = "TIME_AVG"
		},
		{
			name = "BPS OUT",
			field = "evt.buflen.net.out",
			description = "This port's output bandwidth in bytes per second.",
			colsize = 12,
			aggregation = "TIME_AVG"
		},
		{
			name = "IO CALLS",
			field = "evt.count",
			description = "Total (read+write) number of input/output calls made by the process on the connection.",
			colsize = 12,
			aggregation = "SUM"
		}
	},
	actions = 
	{
		{
			hotkey = "t",
			command = "tcpdump -niany port %fd.sport",
			description = "tcpdump port",
			wait_finish = false
		},
	},
}
