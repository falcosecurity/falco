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
description = "List the running containers and the metadata";
short_description = "List the running containers";
category = "System State";
		
-- Argument list
args =
{
		{
				name = "desc",
				description = "Prints the result set as a data structure",
				argtype = "string",
				optional = true
		}
}

-- Imports and globals
require "common"
local dctable = {}
local capturing = false
local filter = nil
local desc = false

-- Argument initialization Callback
function on_set_arg(name, val)
		if name == "desc" and val == "desc" then
				desc = true
				return true
		end

		return false
end

-- Initialization callback
function on_init()
	return true
end

-- Event parsing callback
function on_event()
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
	return true
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end(ts_s, ts_ns, delta)
		if not capturing then
				return
		end

	local ttable = sysdig.get_container_table(filter)

	-- Print out the result set as a data structure
		if ( desc ) then
		print(st(ttable))
		else
	-- Print out the information in a tabular format

		local sorted_ttable = pairs_top_by_val(ttable, 0, function(t,a,b) return a < b end)

		print( extend_string("container.type", 15) ..
			extend_string("container.image", 16) ..
			extend_string("container.name", 20 ) ..
			extend_string("container.id", 13) )
		print( extend_string("---------------", 15) ..
			extend_string("----------------", 16) ..
			extend_string("--------------------", 20 ) ..
			extend_string("-------------", 13) )

		for key, val in sorted_ttable do
			print(extend_string(tostring(val.type), 15) ..
			extend_string(tostring(val.image), 16) ..
			extend_string(tostring(val.name), 20) ..
			extend_string(tostring(val.id), 13)
			)
		end
	end
end
