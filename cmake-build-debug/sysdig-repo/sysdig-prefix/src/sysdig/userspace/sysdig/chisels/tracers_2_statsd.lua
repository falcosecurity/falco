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
description = "Converts sysdig span duration data into statsd metrics and pipes them to the given statsd server. See https://github.com/draios/sysdig/wiki/Tracers for more information.";
short_description = "Export spans duration as statds metrics.";
category = "Tracers";

args =
{
	{
		name = "server_addr",
		description = "The address of the statsd server to send data to",
		argtype = "string",
		optional = true
	},
	{
		name = "server_port",
		description = "The UDP port to use",
		argtype = "string",
		optional = true
	},
}

local lstatsd = require "statsd"
local host = "127.0.0.1"
local port = 8125

-- Argument notification callback
function on_set_arg(name, val)
	if name == "server_addr" then
		host = val
		return true
	elseif name == "server_port" then
		port = tonumber(val)
		return true
	end

	return false
end

-- Initialization callback
function on_init()
	-- Initialize statsd
	statsd = lstatsd({host = "127.0.0.1"})

	-- Request the fields that we need
	ftags = chisel.request_field("span.tags")
	flatency = chisel.request_field("span.duration")
	
	-- set the filter
	chisel.set_filter("evt.type=tracer and evt.dir=<")
	return true
end

-- Event parsing callback
function on_event()
	local tags = evt.field(ftags)
	local latency = evt.field(flatency)

	if latency then
		statsd:timer(tags, tonumber(latency) / 1000000)
	end

	return true
end
