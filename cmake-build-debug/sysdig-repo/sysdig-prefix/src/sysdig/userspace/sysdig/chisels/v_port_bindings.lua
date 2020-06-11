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
	id = "port_bindings",
	name = "Port bindings",
	description = "Lists the creation (bind) and removal (close) of listening ports on the system.",
	tags = {"default", "wsysdig", "nocsysdig"},
	view_type = "list",
	applies_to = {""},
	filter = "(evt.type=bind and evt.dir=< and (fd.type=ipv4 or fd.type=ipv6)) or (evt.type=close and evt.dir=> and fd.typechar=2 and fd.type=ipv4)",
	use_defaults = true,
	columns = 
	{
		{
			name = "TIME",
			field = "evt.time",
			description = "Time when the action happened.",
			colsize = 12,
		},
		{
			name = "OPERATION",
			field = "evt.type",
			description = "Action type. Can Be 'bind' (when a new listening port is added) or 'close' (when a listening port is removed).",
			colsize = 24,
		},
		{
			name = "PORT",
			field = "fd.sport",
			description = "The number of the created/removed port.",
			colsize = 24,
		},
		{
			name = "Command",
			description = "The full command line of the process adding/removing the port.",
			field = "proc.exeline",
			aggregation = "MAX",
			colsize = 0
		}
	}
}
