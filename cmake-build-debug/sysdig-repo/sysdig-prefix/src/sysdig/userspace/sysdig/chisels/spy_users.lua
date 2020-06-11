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
description = "Lists every command that users launch interactively (e.g. from bash) and every directory users visit. This chisel is compatible with containers using the sysdig -pc or -pcontainer argument, otherwise no container information will be shown. (Blue represents a process running within a container, and Green represents a host process)";
short_description = "Display interactive user activity";
category = "Security";

-- Chisel argument list
args =
{
	{
		name = "max_depth",
		description = "the maximum depth to show in the hierarchy of processes",
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

require "common"
terminal = require "ansiterminal"
terminal.enable_color(true)

MAX_ANCESTOR_NAVIGATION = 16
max_depth = -1

-- Argument notification callback
function on_set_arg(name, val)
	if name == "max_depth" then
		max_depth = parse_numeric_input(val, name)
	elseif name == "disable_color" and val == "disable_color" then
		terminal.enable_color(false)
	end

	return true
end

-- Initialization callback
function on_init()
	-- Request the fields needed for this chisel
	fetype = chisel.request_field("evt.type")
	fexe = chisel.request_field("proc.exe")
	fargs = chisel.request_field("proc.args")
	fdir = chisel.request_field("evt.arg.path")
	fuser = chisel.request_field("user.name")
	fdtime = chisel.request_field("evt.time.s")
	fpid = chisel.request_field("proc.pid")
	fppid = chisel.request_field("proc.ppid")
	fcontainername = chisel.request_field("container.name")
	fcontainerid = chisel.request_field("container.id")
	fanames = {}
	fapids = {}

	-- The -pc or -pcontainer options was supplied on the cmd line
	print_container = sysdig.is_print_container_data()

	-- set the filter
	chisel.set_filter("((evt.type=execve and evt.dir=<) or (evt.type=chdir and evt.dir=< and proc.name contains sh and not proc.name contains sshd)) and evt.failed=false")

	for j = 0, MAX_ANCESTOR_NAVIGATION do
		fanames[j] = chisel.request_field("proc.aname[" .. j .. "]")
		fapids[j] = chisel.request_field("proc.apid[" .. j .. "]")
	end

	return true
end

process_tree = {}

-- Event parsing callback
function on_event()

	local color = ""

	-- If -pc or -pcontainer option change default to green
	if  print_container then
		color = terminal.green
	end
		

	local user = evt.field(fuser)
	local dtime = evt.field(fdtime)
	local pid = evt.field(fpid)
	local ppid = evt.field(fppid)
	local ischdir = evt.field(fetype) == "chdir"
	local containername = evt.field(fcontainername)
	local containerid = evt.field(fcontainerid)
	local aname
	local icorr = 1

	if ischdir then
		ppid = pid
		table.insert(fanames, 0, 0)
		table.insert(fapids, 0, 0)
		icorr = 0
	end

	if user == nil then
		user = "<NA>"
	end

	if not process_tree[ppid] then
		-- No parent pid in the table yet.
		-- Add one and make sure that there's a shell among the ancestors
		process_tree[ppid] = {-1}

		for j = 1, MAX_ANCESTOR_NAVIGATION do
			aname = evt.field(fanames[j])

			if aname == nil then
				if evt.field(fapids[j]) == nil then
					-- no shell in the ancestor list, hide this command
					break
				end
			elseif string.len(aname) >= 2 and aname:sub(-2) == "sh" then
				apid = evt.field(fapids[j])
				if process_tree[apid] then
					process_tree[ppid] = {j - 1, apid}
				else
					process_tree[ppid] = {0, apid}
				end
			end
		end
	end

	if process_tree[ppid][1] == -1 then
		-- the parent process has already been detected as NOT having a shell ancestor
		return true
	end

	if not process_tree[pid] then
		process_tree[pid] = {1 + process_tree[ppid][1], process_tree[ppid][2]}
	end

	if ischdir then

		if max_depth ~= -1 then
			if process_tree[pid][1] - icorr > max_depth then
				return true
			end
		end

		-- The -pc or -pcontainer options was supplied on the cmd line
		if  print_container then

			-- Conatiner will print out as blue
			if containername ~= "host" then
				color = terminal.blue
			end

			print(color ..
				  extend_string("", 4 * (process_tree[pid][1] - icorr)) .. process_tree[pid][2] .. " " ..
				  dtime .. " " ..
				  user .. "@" ..
				  containername ..") cd " ..
				  evt.field(fdir))

		else

			print(color ..
				  extend_string("", 4 * (process_tree[pid][1] - icorr)) .. process_tree[pid][2] .. " " ..
				  dtime .. " " ..
				  user .. ") cd " ..
				  evt.field(fdir))

		end
	else
		if max_depth ~= -1 then
			if process_tree[pid][1] - 1 > max_depth then
				return true
			end
		end

		-- The -pc or -pcontainer options was supplied on the cmd line
		if  print_container then

			-- Conatiner will print out as blue
			if containername ~= "host" then
				color = terminal.blue
			end

			print(color ..
				  extend_string("", 4 * (process_tree[pid][1] - 1)) ..  process_tree[pid][2] ..  " " ..
				  dtime .. " " ..
				  user .. "@" ..
				  containername ..") " ..
				  evt.field(fexe) .. " " ..
				  evt.field(fargs))
		else

			print(color ..
				  extend_string("", 3 * (process_tree[pid][1] - 1)) .. process_tree[pid][2] .. " " ..
				  dtime .. " " ..
				  user ..") " ..
				  evt.field(fexe) .. " " ..
				  evt.field(fargs))

		end

-- Tabular format, a future option with potentially a chisel cmd line argument?
--				 print(color .. string.format("%10.10s %-10.10s %-8.8s %-20.20s %-20.20s %-15.15s %s",
--												(process_tree[pid][1] - 1),
--												process_tree[pid][2],
--												dtime,
--												containerid,
--												containername,
--												user,
--												evt.field(fexe) .. " " .. evt.field(fargs)))


	end

	return true
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end()
	print(terminal.reset)
end
