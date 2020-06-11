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
	id = "notifications",
	name = "Notifications",
	description = "Lists the notification events that indicate the specific point in time when sysdig secure policies have been violated.",
	tags = {"nocsysdig"},
	view_type = "list",
	applies_to = {""},
	filter = "evt.type=notification",
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
			name = "ID",
			field = "evt.arg.id",
			description = "Notification ID. This can be used to locate the notification in the sysdig secure user interface.",
			colsize = 24,
		},
		{
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			colsize = 20
		},
		{
			name = "DESCRIPTION",
			field = "evt.arg.desc",
			description = "The description of the policy that generated this notification.",
			colsize = 0,
		}
	}
}
