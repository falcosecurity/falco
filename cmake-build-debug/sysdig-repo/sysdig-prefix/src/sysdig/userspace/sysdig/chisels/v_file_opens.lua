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
	id = "file_opens",
	name = "File Opens List",
	description = "List file name and process for of every single file open.",
	tips = {"The RES column is very useful to identify failed opens. Successful opens will show 'SUCCESS' in this column, while failed opens will show an errno code. Do a 'man errno' to find the meaning of the most important codes. And remember that you can sort the opens based on this code, or filter for specific codes using the F4 key."},
	tags = {"Default"},
	view_type = "list",
	applies_to = {"", "container.id", "proc.pid", "thread.nametid", "proc.name", "thread.tid", "fd.sport", "fd.sproto", "fd.name", "fd.containername", "fd.directory", "fd.containerdirectory", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "evt.type=open and evt.dir=<",
	columns = 
	{
		{
			name = "TIME",
			field = "evt.time",
			description = "The timestamp of the file open.",
			colsize = 19,
		},
		{
			name = "RES",
			field = "evt.res",
			description = "The result of the open call. This can be either 'SUCCESS', or an errno code.",
			colsize = 8,
		},
		{
			name = "FILE",
			field = "fd.name",
			description = "The file name.",
			colsize = 40,
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
			field = "proc.exeline",
			aggregation = "MAX",
			description = "The program that opened the file, including its arguments.",
			colsize = 0,
		}		
	},
	actions = 
	{
		{
			hotkey = "l",
			command = "less %fd.name",
			description = "less file",
			wait_finish = false
		},
	},
}
