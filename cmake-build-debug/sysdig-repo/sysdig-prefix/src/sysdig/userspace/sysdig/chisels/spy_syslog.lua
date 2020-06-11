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
description = "Print every message written to syslog by any process. You can combine this chisel with filters like 'proc.name=foo' (to restrict the output to a specific process), or 'syslog.message contains foo' (to show only messages including a specific string). You can also write the events generated around each log entry to file by using the dump_file_name and dump_range_ms arguments.";
short_description = "Print every message written to syslog. Optionally, export the events around each syslog message to file.";
category = "Logs";
		
-- Argument list
args =
{
	{
		name = "dump_file_name",
		description = "The name of the file where the chisel will write the events related to each syslog entry.",
		argtype = "string",
		optional = true
	},
	{
		name = "dump_range_ms",
		description = "The time interval to capture *before* and *after* each event, in milliseconds. For example, 500 means that 1 second around each displayed event (.5s before and .5s after) will be saved to <dump_file_name>. The default value for dump_range_ms is 1000.",
		argtype = "int",
		optional = true
	},
	{
		name = "disable_color",
		description = "Set to 'disable_colors' if you want to disable color output",
		argtype = "string",
		optional = true
	},
}
-- Imports and globals
require "common"
terminal = require "ansiterminal"
terminal.enable_color(true)
local do_dump = false
local dump_file_name = nil
local dump_range_ms = "1000"
local entrylist = {}
local capturing = false

-- Argument notification callback
function on_set_arg(name, val)
	if name == "dump_file_name" then
		do_dump = true
		dump_file_name = val
		return true
	elseif name == "dump_range_ms" then
		dump_range_ms = val
		return true
	elseif name == "disable_color" and val == "disable_color" then
		terminal.enable_color(false)
		return true
	end

	return false
end

-- Initialization callback
function on_init()	
	-- Request the fields that we need
	ffac = chisel.request_field("syslog.facility.str")
	fsev = chisel.request_field("syslog.severity.str")
	fsevcode = chisel.request_field("syslog.severity")
	fmsg = chisel.request_field("syslog.message")
	ftid = chisel.request_field("thread.tid")
	fpname = chisel.request_field("proc.name")
	fcontainername = chisel.request_field("container.name")
	fcontainerid = chisel.request_field("container.id")

	-- The -pc or -pcontainer options was supplied on the cmd line
	print_container = sysdig.is_print_container_data()

	-- increase the snaplen so we capture more of the conversation
	sysdig.set_snaplen(1000)
	
	-- set the filter
	chisel.set_filter("fd.name contains /dev/log and evt.is_io_write=true and evt.dir=< and evt.failed=false")
	
	is_tty = sysdig.is_tty()
	
	return true
end

-- Final chisel initialization
function on_capture_start()
	if do_dump then
		if sysdig.is_live() then
			print("events export not supported on live captures")
			return false
		end
	end
	
	capturing = true

	return true
end

-- Event parsing callback
function on_event()	

	local color = ""

	-- Extract the event details
	local fac = evt.field(ffac)
	local sev = evt.field(fsev)
	local msg = evt.field(fmsg)
	local sevcode = evt.field(fsevcode)
	local tid = evt.field(ftid)
	local pname = evt.field(fpname)
	local containername = evt.field(fcontainername)
	local containerid = evt.field(fcontainerid)
	
	-- Render the message to screen
	if is_tty then
		local color = terminal.green
		
		if sevcode == 4 then
			color = terminal.yellow
		elseif sevcode < 4 then
			color = terminal.red
		elseif containername ~= "host" then
			-- If -pc or -pcontainer option change default to blue
			color = terminal.blue
		else
			color = terminal.green
		end

		-- The -pc or -pcontainer options was supplied on the cmd line
		if  print_container then
			infostr = string.format("%s%-20s %-20s %s.%s %s[%u] %s",
									color,
									containerid,
									containername,
									fac,
									sev,
									pname,
									tid,
									msg)
		else
			infostr = string.format("%s%s.%s %s[%u] %s",
									color,
									fac,
									sev,
									pname,
									tid,
									msg)
		end
	else
		if  print_container then
			infostr = string.format("%-20s %-20s %s.%s %s[%u] %s",
									fac,
									containerid,
									containername,
									sev,
									pname,
									tid,
									msg)
		else
			infostr = string.format("%s.%s %s[%u] %s",
									fac,
									sev,
									pname,
									tid,
									msg)
		end
	end
	
	print(infostr)
	
	if do_dump then
		local hi, low = evt.get_ts()
		table.insert(entrylist, {hi, low, tid})
	end
			
	return true
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end()
	if is_tty then
		print(terminal.reset)
	end

	if do_dump then
		if capturing then
			local sn = sysdig.get_evtsource_name()

			local args = "-F -r" .. sn .. " -w" .. dump_file_name .. " "
			
			for i, v in ipairs(entrylist) do
				if i ~= 1 then
					args = args .. " or "
				end
				
				args = args .. "(evt.around[" .. ts_to_str(v[1], v[2]) .. "]=" .. dump_range_ms .. " and thread.tid=" .. v[3] .. ")"
			end		

			print("Writing events for " .. #entrylist .. " log entries")
			sysdig.run_sysdig(args)
		end
	end
end
