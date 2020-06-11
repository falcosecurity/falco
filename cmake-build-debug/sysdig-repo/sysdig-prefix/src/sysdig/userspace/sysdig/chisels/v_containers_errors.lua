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
	id = "containers_errors",
	name = "Containers Errors",
	description = "This view shows system error counters for each container running on the machine. Errors are grouped into 4 categories: file I/O, network I/O, memory allocation and 'other'.",
	tips = {
		"If you click 'enter' on a selection in this chart, you will be able to see the specific errors that the container is generating.",
		"Digging into a container by clicking on F6 will let you explore the system calls for that specific container and see the full details about what's causing the errors."
	},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "container.id", "fd.name", "fd.containername", "fd.sport", "fd.sproto", "evt.type", "fd.directory", "fd.containerdirectory", "fd.containerdirectory", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	drilldown_target = "errors",
	filter = "container.name != host",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
		},
		{
			name = "ID",
			field = "container.id",
			is_groupby_key = true
		},
		{
			name = "FILE",
			field = "evt.count.error.file",
			description = "Number of file I/O errors generated in the container during the sample interval. On trace files, this is the total for the whole file.",
			colsize = 8,
			aggregation = "SUM",
			groupby_aggregation = "SUM"
		},
		{
			name = "NET",
			field = "evt.count.error.net",
			description = "Number of network I/O errors generated in the container during the sample interval. On trace files, this is the total for the whole file.",
			colsize = 8,
			aggregation = "SUM",
			groupby_aggregation = "SUM"
		},
		{
			name = "MEMORY",
			field = "evt.count.error.memory",
			description = "Number of memory allocation/release related errors generated in the container during the sample interval. On trace files, this is the total for the whole file.",
			colsize = 8,
			aggregation = "SUM",
			groupby_aggregation = "SUM"
		},
		{
			name = "OTHER",
			field = "evt.count.error.other",
			description = "Number of errors generated in the container that don't fall in any of the previous categories. E.g. signal or event related errors. On trace files, this is the total for the whole file.",
			colsize = 8,
			aggregation = "SUM",
			groupby_aggregation = "SUM"
		},
		{
			name = "ENGINE",
			field = "container.type",
			description = "Container type.",
			colsize = 8
		},
		{
			name = "ID",
			field = "container.id",
			description = "Container ID. The format of this column depends on the containerization technology. For example, Docker ID are 12 characters hexadecimal digit strings.",
			colsize = 13
		},
		{
			name = "CONTAINER",
			field = "container.name",
			description = "Name of the container. What this field contains depends on the containerization technology. For example, for docker this is the content of the 'NAMES' column in 'docker ps'",
			colsize = 0
		}
	},
	actions = 
	{
		{
			hotkey = "a",
			command = "docker attach %container.id",
			description = "docker attach"
		},
		{
			hotkey = "b",
			command = "docker exec -i -t %container.id /bin/bash",
			description = "bash shell",
			wait_finish = false
		},
		{
			hotkey = "f",
			command = "docker logs -f %container.id",
			description = "follow logs"
		},
		{
			hotkey = "h",
			command = "docker history %container.image",
			description = "image history"
		},
		{
			hotkey = "i",
			command = "docker inspect %container.id",
			description = "docker inspect"
		},
		{
			hotkey = "k",
			command = "docker kill %container.id",
			description = "docker kill",
			ask_confirmation = true
		},
		{
			hotkey = "l",
			command = "docker logs %container.id",
			description = "docker logs"
		},
		{
			hotkey = "s",
			command = "docker stats %container.id",
			description = "docker stop"
		},
		{
			hotkey = "z",
			command = "docker pause %container.id",
			description = "docker pause"
		},
		{
			hotkey = "u",
			command = "docker unpause %container.id",
			description = "docker unpause"
		},
		{
			hotkey = "w",
			command = "docker wait %container.id",
			description = "docker wait"
		},
	},
}
