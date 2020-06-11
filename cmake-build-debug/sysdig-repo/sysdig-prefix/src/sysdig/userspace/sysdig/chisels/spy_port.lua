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
description = "Shows the network payloads exchanged using a given IP port number. You can combine this chisel with the -x, -X or -A sysdig command line switches to customize the screen output";
short_description = "Show the data exchanged using the given IP port number";
category = "Net";

-- Chisel argument list
args = 
{
	{
		name = "host_port",
		description = "The remote host IP port number", 
		argtype = "int"
	},
	{
		   name = "disable_color",
		   description = "Set to 'disable_colors' if you want to disable color output",
		   argtype = "string",
		   optional = true
	},
}

require "common"
terminal = require "ansiterminal"
terminal.enable_color(true)

-- Argument notification callback
function on_set_arg(name, val)
    if name == "host_port" then
        port = val
        return true
    elseif name == "disable_color" then
        if val == "disable_colors" then
            terminal.enable_color(false)
        end
        return true
    end
    return false
end

-- Initialization callback
function on_init()
	-- Request the fields that we need
	fdata = chisel.request_field("evt.arg.data")
	fisread = chisel.request_field("evt.is_io_read")
	fres = chisel.request_field("evt.rawarg.res")

	-- increase the snaplen so we capture more of the conversation 
	sysdig.set_snaplen(1000)

	-- set the filter
        chisel.set_filter("evt.is_io=true and (fd.type=ipv4 or fd.type=ipv6) and fd.port=" .. port )
	return true
end

DIR_READ = 1
DIR_WRITE = 2

direction = nil

-- Event parsing callback
function on_event()
	res = evt.field(fres)
	data = evt.field(fdata)
	
	if res == nil or res <= 0 then
		return true
	end

	if data ~= nil then
		isread = evt.field(fisread)	
		
		if isread and direction ~= DIR_READ then
			infostr = string.format("%s------ Read %s", terminal.red, format_bytes(res))
			direction = DIR_READ
		elseif not isread and direction ~= DIR_WRITE then
			infostr = string.format("%s------ Write %s", terminal.blue, format_bytes(res))
			direction = DIR_WRITE
		end

		print(infostr)
		print(data)
	end

	return true
end

function on_capture_end()
	print(terminal.reset)
end
