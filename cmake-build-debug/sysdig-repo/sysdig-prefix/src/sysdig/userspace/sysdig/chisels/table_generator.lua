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
description = "Given two filter fields, a key and a value, this chisel creates and renders a table to the screen."
short_description = "Filter on a key and value"
category = "Filter"
hidden = true

-- Chisel argument list
args =
{
	{
		name = "keys",
		description = "comma-separated list of filter fields to use for grouping",
		argtype = "string"
	},
	{
		name = "keydescs",
		description = "comma separated list of human readable descriptions for the key",
		argtype = "string"
	},
	{
		name = "value",
		description = "the value to count for every key",
		argtype = "string"
	},
	{
		name = "valuedesc",
		description = "human readable description for the value",
		argtype = "string"
	},
	{
		name = "filter",
		description = "the filter to apply",
		argtype = "string"
	},
	{
		name = "top_number",
		description = "maximum number of elements to display",
		argtype = "string"
	},
	{
		name = "value_units",
		description = "how to render the values in the result. Can be 'bytes', 'time', 'timepct', or 'none'.",
		argtype = "string"
	},
}

require "common"
terminal = require "ansiterminal"

grtable = {}
filter = ""
islive = false
fkeys = {}

vizinfo =
{
	key_fld = {},
	key_desc = {},
	value_fld = "",
	value_desc = "",
	value_units = "none",
	top_number = 0,
	output_format = "normal"
}

-- Argument notification callback
function on_set_arg(name, val)
	if name == "keys" then
		vizinfo.key_fld = split(val, ",")		
		return true
	elseif name == "keydescs" then
		vizinfo.key_desc = split(val, ",")
		return true
	elseif name == "value" then
		vizinfo.value_fld = val
		return true
	elseif name == "valuedesc" then
		vizinfo.value_desc = val
		return true
	elseif name == "filter" then
		filter = val
		return true
	elseif name == "top_number" then
		vizinfo.top_number = tonumber(val)
		return true
	elseif name == "value_units" then
		vizinfo.value_units = val
		return true
	end

	return false
end

-- Initialization callback
function on_init()
	if #vizinfo.key_fld ~= #vizinfo.key_desc then
		print("error: number of entries in keys different from number entries in keydescs")
		return false
	end

	-- Request the fields we need
	for i, name in ipairs(vizinfo.key_fld) do
		fkeys[i] = chisel.request_field(name)
	end

	fvalue = chisel.request_field(vizinfo.value_fld)

	-- set the filter
	if filter ~= "" then
		chisel.set_filter(filter)
	end
	
	return true
end

-- Final chisel initialization
function on_capture_start()
	islive = sysdig.is_live()
	vizinfo.output_format = sysdig.get_output_format()

	if islive then
		chisel.set_interval_s(1)
		if vizinfo.output_format ~= "json" then
			terminal.clearscreen()
			terminal.hidecursor()
		end
	end
	
	return true
end

-- Event parsing callback
function on_event()
	local key = nil
	local kv = nil
	
	for i, fld in ipairs(fkeys) do
		kv = evt.field(fld)
		if kv == nil then
			return
		end

		if key == nil then
			key = kv
		else
			key = key .. "\001\001" .. evt.field(fld)
		end
	end
	
	value = evt.field(fvalue)

	if value ~= nil and value > 0 then
		entryval = grtable[key]

		if entryval == nil then
			grtable[key] = value
		else
			grtable[key] = grtable[key] + value
		end
	end

	return true
end

-- Periodic timeout callback
function on_interval(ts_s, ts_ns, delta)	
	if vizinfo.output_format ~= "json" then
		terminal.clearscreen()
		terminal.moveto(0, 0)
	end
	
	print_sorted_table(grtable, ts_s, 0, delta, vizinfo)

	-- Clear the table
	grtable = {}
	
	return true
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end(ts_s, ts_ns, delta)
	if islive and vizinfo.output_format ~= "json" then
		terminal.clearscreen()
		terminal.moveto(0 ,0)
		terminal.showcursor()
		return true
	end
	
	print_sorted_table(grtable, ts_s, 0, delta, vizinfo)
	
	return true
end
