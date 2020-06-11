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
	id = "spy_users",
	name = "Spy Users",
	description = "Lists all the commands that are run interactively, i.e. that have a shell as the parent process. The result is the display of all the user activity, sorted by time.",
	tags = {"Default"},
	view_type = "list",
	applies_to = {"", "container.id", "proc.pid", "thread.nametid", "thread.tid", "proc.name", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "((evt.type=execve and evt.dir=<) or (evt.type=chdir and evt.dir=< and proc.name contains sh and not proc.name contains sshd)) and evt.failed=false",
	use_defaults = true,
	columns = 
	{
		{
			name = "TIME",
			field = "evt.time",
			description = "Time when the command was executed.",
			colsize = 12,
		},
		{
			name = "USER",
			field = "user.name",
			description = "Name of the user running the command.",
			colsize = 12,
		},
		{
			name = "SHELL",
			field = "proc.ppid",
			description = "Pid of the shell where this command was executed. This, essentially, corresponds to a 'session ID'. You can filer or sort by this column to isolate a specific interactive user session.",
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
			field = "proc.exeline",
			aggregation = "MAX",
			description = "The executed command, including arguments.",
			colsize = 0
		}		
	}
}
