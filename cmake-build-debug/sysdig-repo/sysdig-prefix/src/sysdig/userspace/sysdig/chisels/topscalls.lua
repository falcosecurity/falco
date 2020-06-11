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

-- The number of items to show
TOP_NUMBER = 30

-- Chisel description
description = "Show the top " .. TOP_NUMBER .. " system calls in terms of number of calls. You can use filters to restrict this to a specific process, thread or file. This chisel is compatible with containers using the sysdig -pc or -pcontainer argument, otherwise no container information will be shown."
short_description = "Top system calls by number of calls"
category = "Performance"

-- Chisel argument list
args = {}

-- Argument notification callback
function on_set_arg(name, val)
	return false
end

-- Initialization callback
function on_init()

	-- The -pc or -pcontainer options was supplied on the cmd line
	print_container = sysdig.is_print_container_data()

	if print_container then
		chisel.exec("table_generator",
					"evt.type,container.name",
					"Syscall,container.name",
					"evt.count",
					"# Calls",
					"evt.type!=switch",
					"" .. TOP_NUMBER,
					"none")
	else
		chisel.exec("table_generator",
					"evt.type",
					"Syscall",
					"evt.count",
					"# Calls",
					"evt.type!=switch",
					"" .. TOP_NUMBER,
					"none")
	end

	return true
end
