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
	id = "incoming_connections",
	name = "New Connections",
	description = "List every newly established network connection.",
	tags = {"Default"},
	view_type = "list",
	applies_to = {"", "container.id", "proc.pid", "thread.nametid", "thread.tid", "proc.name", "fd.name", "fd.containername", "fd.sport", "fd.sproto", "fd.dport", "fd.port", "fd.lport", "fd.rport", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "evt.type=accept and evt.dir=< and evt.failed=false",
	columns = 
	{
		{
			name = "TIME",
			field = "evt.time",
			description = "Time when the connection was received by this machine.",
			colsize = 19,
		},
		{
			name = "Connection",
			field = "fd.name",
			description = "Connection tuple details.",
			colsize = 40,
		},
		{
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			description = "Name of the container. This field depends on the containerization technology. For docker this is the 'NAMES' column in 'docker ps'",
			colsize = 20
		},
		{
			name = "Command",
			field = "proc.exeline",
			aggregation = "MAX",
			description = "Name and arguments of the process that received the connection.",
			colsize = 0
		}		
	}
}
