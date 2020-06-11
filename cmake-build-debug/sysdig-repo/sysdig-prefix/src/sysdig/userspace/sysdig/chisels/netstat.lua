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
description = "Print the system network connections, with an output that is similar to the one of netstat. Output is at a point in time; adjust this in the filter. It defaults to time of evt.num=0";
short_description = "List (and optionally filter) network connections.";
category = "System State";
		
-- Argument list
args =
{
	{
		name = "filter",
		description = "A sysdig-like filter expression that allows restricting the FD list. E.g. 'proc.name=foo and fd.port=80'.",
		argtype = "filter",
		optional = true
	}
}

-- Argument initialization Callback
function on_set_arg(name, val)
	if name == "filter" then
		filter = val
		return true
	end

	return false
end

-- Imports and globals
require "common"
local dctable = {}
local capturing = false
local filter = "(fd.type=ipv4 or fd.type=ipv6)"
local match = false

-- Argument notification callback
function on_set_arg(name, val)
	if name == "filter" then
		filter = filter .. "and (" .. val .. ")"
		return true
	end

	return false
end

-- Initialization callback
function on_init()
	return true
end

-- Final chisel initialization
function on_capture_start()	
	capturing = true
	return true
end

-- Event parsing callback
function on_event()
	sysdig.end_capture()
	match = true
	return false
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end()
	if not capturing then
		return
	end
	
	if match == false then
		print("empty capture or no event matching the filter")
		return
	end

	local ttable = sysdig.get_thread_table(filter)

	print(extend_string("Proto", 6) ..
		extend_string("Server Address", 25) ..
		extend_string("Client Address", 25) ..
		extend_string("State", 15) ..
		"TID/PID/Program Name")

	for tid, proc in pairs(ttable) do
		local fdtable = proc.fdtable
		
		for fd, fdinfo in pairs(fdtable) do
			local cip = fdinfo.cip
			local cport = fdinfo.cport
			local state = "ESTABLISHED"

			if cip == nil then
				cip = "0.0.0.0"
				cport = "*"
				state = "LISTEN"
			end

			print(extend_string(fdinfo.l4proto, 6) ..
				extend_string(fdinfo.sip .. ":" .. fdinfo.sport, 25) ..
				extend_string(cip .. ":" .. cport, 25) ..
				extend_string(state, 15) ..
				tid .. "/" .. proc.pid .. "/" .. proc.comm
				)
		end
	end
end
