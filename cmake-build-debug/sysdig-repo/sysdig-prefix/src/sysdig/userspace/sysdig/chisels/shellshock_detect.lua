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
description = "Reports every attempt to execute bash in a way that exploits the shellshock vulnerability (http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-6271). For every attempt, the chisel reports the time, the name of the process trying to run bash, and its PID.";
short_description = "print shellshock attacks";
category = "Security";

args = {}

require "common"

-- Initialization callback
function on_init()
	-- Request the fields that we need
	fpname = chisel.request_field("proc.pname")
	fppid = chisel.request_field("proc.ppid")
	fpid = chisel.request_field("proc.pid")
	fenv = chisel.request_field("evt.arg.environment")
	fetime = chisel.request_field("evt.time")

	-- set the filter
	chisel.set_filter("proc.name=bash or proc.name=sh and evt.type=execve")
	
	print(extend_string("TIME", 22) ..
		extend_string("PROCNAME", 22) ..
		extend_string("PID", 8) ..
		"FUNCTION")

	return true
end

-- Event parsing callback
function on_event()
	local env = evt.field(fenv)
	local pname = evt.field(fpname)
	local etime = evt.field(fetime)
	local ppid = evt.field(fppid)
	
	if env ~= nil then
		if string.find(env, "%(%) ?{.+") then
			local pid = evt.field(fpid)
			local env_list = sysdig.get_thread_table(filter)[pid].env
			
			for i, v in ipairs(env_list) do
				if string.find(v, "%(%) ?{.+") then
					local command = string.match(v, "%(%).+")

					print(extend_string(etime, 22) ..
						extend_string(pname, 22) ..
						extend_string(tostring(ppid), 8) ..
						command)
					break
				end
			end
		end
	end
	
	return true
end
