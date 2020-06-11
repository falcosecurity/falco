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
description = "Counts the total bytes read from and written to the network, and prints the result every second";
short_description = "Show total network I/O bytes";
category = "Net";

-- Chisel argument list
args = {}

tot = 0
totin = 0
totout = 0

-- Initialization callback
function on_init()
	-- Request the fields
	fbytes = chisel.request_field("evt.rawarg.res")
	ftime = chisel.request_field("evt.time.s")
	fisread = chisel.request_field("evt.is_io_read")

	-- set the filter
	chisel.set_filter("evt.is_io=true and (fd.type=ipv4 or fd.type=ipv6)")
	
	chisel.set_interval_s(1)
	
	return true
end

-- Event parsing callback
function on_event()
	bytes = evt.field(fbytes)
	isread = evt.field(fisread)

	if bytes ~= nil and bytes > 0 then
		tot = tot + bytes
		
		if isread then
			totin = totin + bytes
		else
			totout = totout + bytes
		end
	end

	return true
end

function on_interval(delta)
	etime = evt.field(ftime)

	print(etime .. " in:" .. totin .. " out:" .. totout .. " tot:" .. tot)
	tot = 0
	totin = 0
	totout = 0
	return true
end
