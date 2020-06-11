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
description = "List the running processes, with an output that is similar to the one of ps. Output is at a point in time; adjust this in the filter. It defaults to time of evt.num=0";
short_description = "List (and optionally filter) the machine processes.";
category = "System State";
		
-- Argument list
args =
{
	{
		name = "filter",
		description = "A sysdig-like filter expression that allows restricting the FD list. For example 'fd.name contains /etc' shows all the processes that have files open under /etc.",
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
local filter = nil
local match = false

-- Argument notification callback
function on_set_arg(name, val)
	if name == "filter" then
		filter = val
		return true
	end

	return false
end

-- Initialization callback
function on_init()
	return true
end

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
function on_capture_end(ts_s, ts_ns, delta)
	if not capturing then
		return
	end
	
	if match == false then
		print("empty capture or no event matching the filter")
		return
	end
	
	local ttable = sysdig.get_thread_table(filter)

	local sorted_ttable = pairs_top_by_val(ttable, 0, function(t,a,b) return a < b end)
	
	print(extend_string("TID", 8) ..
		extend_string("PID", 8) ..
		extend_string("USER", 12) ..
		extend_string("VIRT", 11) ..
		extend_string("RES", 11) ..
		extend_string("FDLIMIT", 10) ..
		extend_string("CMD", 20))

	for tid, proc in sorted_ttable do
		print(extend_string(tostring(tid), 8) ..
			extend_string(tostring(proc.pid), 8) ..
			extend_string(proc.username, 12) ..
			extend_string(format_bytes(proc.vmsize_kb * 1024), 11) ..
			extend_string(format_bytes(proc.vmrss_kb * 1024), 11) ..
			extend_string(tostring(proc.fdlimit), 10) ..
			proc.comm
			)
	end
end
