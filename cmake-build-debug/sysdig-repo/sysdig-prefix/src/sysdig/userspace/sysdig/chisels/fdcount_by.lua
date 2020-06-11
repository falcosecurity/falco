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
description = "Groups all the active FDs based on the given filter field, and returns the fd count for each key. For example, it can be used to list the number of connections per process or per IP endpoint."
short_description = "FD count, aggregated by an arbitrary filter field"
category = "I/O"

-- Chisel argument list
args =
{
	{
		name = "key",
		description = "The filter field used for grouping",
		argtype = "string"
	},
}

-- The number of items to show
TOP_NUMBER = 0

require "common"

grtable = {}
key_fld = ""

-- Argument notification callback
function on_set_arg(name, val)
	if name == "key" then
		key_fld = val
		return true
	end

	return false
end

-- Initialization callback
function on_init()
	-- Request the fields we need
	fkey = chisel.request_field(key_fld)
	ffdnum = chisel.request_field("fd.num")
	ffdname = chisel.request_field("fd.name")
	
	return true
end

-- Event parsing callback
function on_event()
	key = evt.field(fkey)
	fdnum = evt.field(ffdnum)
	fdname = evt.field(ffdname)

	if key ~= nil and fdnum ~= nil and fdnum > 0 and fdname ~= nil and fdname ~= "" then
		entryval = grtable[key]
		fdkey = tostring(fdnum) .. fdname

		if entryval == nil then
			grtable[key] = {}
			grtable[key][fdkey] = 1
			grtable[key]["c"] = 1
		else
			fdentry = grtable[key][fdkey]
			
			if fdentry == nil then
				grtable[key][fdkey] = 1
				grtable[key]["c"] = grtable[key]["c"] + 1
			end
		end
	end

	return true
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end()
	sorted_grtable = pairs_top_by_val(grtable, TOP_NUMBER, function(t,a,b) return t[b]["c"] < t[a]["c"] end)
	
	etime = evt.field(ftime)

	for k,v in sorted_grtable do
		print(k, v["c"])
	end
	
	return true
end
