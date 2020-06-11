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
	id = "directories",
	name = "Directories",
	description = "This view lists the directories that were accessed on the file system. The list can be sorted by metrics like the input/output bytes and the IOPS",
	tips = {"This view can be applied not only to the whole machine, but also to single processes, containers, threads and so on. Use it after a drill down for more fine grained investigation."},
	tags = {"Default", "wsysdig"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "thread.nametid", "proc.name", "thread.tid", "fd.sport", "fd.sproto", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "fd.type=file or fd.type=directory and fd.name!=''",
	use_defaults = true,
	drilldown_target = "files",
	columns = 
	{
		{
			tags = {"default"},
			name = "NA",
			field = "fd.directory",
			is_key = true
		},
		{
			tags = {"containers"},
			name = "NA",
			field = "fd.containerdirectory",
			is_key = true
		},
		{
			name = "BYTES IN",
			field = "evt.buflen.file.in",
			description = "Amount of bytes read from the file. For live captures, this is the amount during the last sampling interval. For trace files, this is the total amount for the full file.",
			colsize = 12,
			aggregation = "SUM"
		},
		{
			name = "BYTES OUT",
			field = "evt.buflen.file.out",
			description = "amount of bytes written to the file. For live captures, this is the amount during the last sampling interval. For trace files, this is the total amount for the full file.",
			colsize = 12,
			aggregation = "SUM"
		},
		{
			is_sorting = true,
			name = "OPS",
			field = "evt.count.exit",
			description = "Number of I/O operations on the file. This counts all the operations on the file, including, open, close, read, write, stat, and so on. As a consequence, this value can be nonzero even if I/O bytes for the file are zero.",
			colsize = 9,
			aggregation = "SUM"
		},
		{
			name = "OPENS",
			field = "evt.type.is.3",
			description = "Number times the file has been opened.",
			colsize = 9,
			aggregation = "SUM"
		},
		{
			name = "ERRORS",
			field = "evt.count.error",
			description = "Number I/O errors that happened on this file.",
			colsize = 9,
			aggregation = "SUM"
		},
		{
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			colsize = 20
		},
		{
			name = "DIRNAME",
			description = "The full directory path name.",
			field = "fd.directory",
			colsize = 0
		}
	};
	actions = 
	{
		{
			hotkey = "l",
			command = "ls -al %fd.directory",
			description = "ls directory"
		},
	},
}
