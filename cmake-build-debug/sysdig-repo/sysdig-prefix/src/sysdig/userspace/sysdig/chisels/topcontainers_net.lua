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
description = "Sorted list of containers that use the most network bandwidth."
short_description = "Top containers by network I/O"
category = "Net"

-- Chisel argument list
args = {}

-- Initialization callback
function on_init()
	chisel.exec("table_generator",
		"container.name",
		"container.name",
		"evt.rawarg.res",
		"Bytes",
		"(fd.type=ipv4 or fd.type=ipv6) and evt.is_io=true and container.name!=host",
		"100",
		"bytes")
		
	return true
end
