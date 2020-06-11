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
description = "List the IDs of the login sessions. Optionally, the list can be filtered to include only the sessions that contain a specific command. The session IDs listed by this chisel can be used as filters for the spy_users chisel. This chisel is compatible with containers using the sysdig -pc or -pcontainer argument, otherwise no container information will be shown.";
short_description = "List the login shell IDs";
category = "Security";

-- Chisel argument list
args =
{
	{
		name = "command",
		description = "If this parameter is specified, only the login shells that contain commands including the given string in their name will be listed. * will match any command name.",
		argtype = "string",
		optional = true
	},
	{
		name = "arguments",
		description = "If this parameter is specified, only the login shells that contain commands including the given string in their arguments will be listed",
		argtype = "string",
		optional = true
	},
}

require "common"

sids =
{
   fsid = nil,
   containername = nil,
   containerid = nil
}

-- Argument notification callback
function on_set_arg(name, val)
	if name == "command" then
		if val ~= "*" then
			matching_comm_str = val
		end
	elseif name == "arguments" then
		matching_arg_str = val
	end
	return true
end

-- Initialization callback
function on_init()
	fsid = chisel.request_field("proc.loginshellid")
	fexe = chisel.request_field("evt.arg.exe")
	fargs = chisel.request_field("evt.arg.args")
	fcontainername = chisel.request_field("container.name")
	fcontainerid = chisel.request_field("container.id")

	-- The -pc or -pcontainer options was supplied on the cmd line
	print_container = sysdig.is_print_container_data()
	
	chisel.set_filter("evt.type=execve")
		
	return true
end

-- Event parsing callback
function on_event()

	sid = evt.field(fsid)
	exe = evt.field(fexe)
	args = evt.field(fargs)
	containername = evt.field(fcontainername)
	containerid = evt.field(fcontainerid)
	
	if sid and exe then
		if matching_comm_str and string.find(exe, matching_comm_str) == nil then
			return true
		end
		
		if matching_arg_str and args and string.find(args, matching_arg_str) == nil then
			return true
		end
		
		sids.fsid = sid
		sids.containername = containername
		sids.containerid = containerid
	end
	
	return true
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end()
	if matching_comm_str then
		print("Shells containing " .. matching_comm_str .. ":")
	else
		print("All shells:")
	end
	
	for k, v in pairs(sids) do

		-- The -pc or -pcontainer options was supplied on the cmd line
		if  print_container then
			print(sids.fsid .. " " .. sids.containername .. " " .. sids.containerid)
		else
			print(sids.fsid)
		end
	end
end
