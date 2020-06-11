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

-- Chisel description
description = "Sort the list of the processes that use the most network bandwidth. This chisel is compatible with containers using the sysdig -pc or -pcontainer argument, otherwise no container information will be shown."
short_description = "Top processes by network I/O"
category = "Net"

-- Chisel argument list
args = {}

-- Initialization callback
function on_init()


	-- The -pc or -pcontainer options was supplied on the cmd line
	print_container = sysdig.is_print_container_data()

	if print_container then
		chisel.exec("table_generator",
					"proc.name,proc.pid,thread.vtid,container.name",
					"Process,Host_pid,Container_pid,container.name",
					"evt.rawarg.res",
					"Bytes",
					"(fd.type=ipv4 or fd.type=ipv6) and evt.is_io=true",
					"100",
					"bytes")
	else
		chisel.exec("table_generator",
					"proc.name,proc.pid",
					"Process,PID",
					"evt.rawarg.res",
					"Bytes",
					"(fd.type=ipv4 or fd.type=ipv6) and evt.is_io=true",
					"100",
					"bytes")
	end

		
	return true
end
