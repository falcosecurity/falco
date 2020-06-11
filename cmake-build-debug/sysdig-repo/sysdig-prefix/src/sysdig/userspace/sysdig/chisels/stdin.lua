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
description = "Print the standard input of any process on screen. Combine this script with a filter to limit the output to a specific process or pid.";
short_description = "Print stdin of processes";
category = "I/O";

args = {}

-- Initialization callback
function on_init()
	-- Request the fields that we need
	fbuf = chisel.request_field("evt.rawarg.data")

	-- increase the snaplen so we capture more of the conversation 
	sysdig.set_snaplen(2000)

	-- set the filter
	chisel.set_filter("fd.num=0 and evt.is_io=true")
	
	return true
end

-- Event parsing callback
function on_event()
	buf = evt.field(fbuf)
	
	if buf ~= nil then
		print(buf)
	end
	
	return true
end
