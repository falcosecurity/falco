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
description = "internal chisel, creates the json for the wsysdig summary page."
short_description = "wsysdig summary generator"
category = "NA"
hidden = true

-- Imports and globals
require "common"

-- Chisel argument list
args =
{
	{
		name = "composite_args",
		description = "The number of events in the file. If this argument is not specified, the chisel will just scan the file, compute the number of events and then relaunch itself with the number as argument.",
		argtype = "int",
		optional = true
	}
}

local disable_index = true	-- change this if you are working on this script and don't want to be bothered by indexing
local n_samples = 400
local sampling_period = 0
local arg_n_timeline_samples = n_samples
local json = require ("dkjson")
local gsummary = {} -- The global summary
local ssummary = {} -- Last sample's summary
local nintervals = 0
local file_cache_exists = false
local arg_file_duration = nil
local evtcnt = 0
local index_format_version = 1	-- Increase this if the content or the format of the output changes.
								-- An increase in this number will cause existing indexes to be discharged.

-- Argument notification callback
function on_set_arg(name, val)
	if name == "composite_args" then
		vals = split(val, ",")

		local val1n = tonumber(vals[1])

		if val1n ~= 0 and val1n < n_samples then
			arg_n_timeline_samples = val1n
		end
		
		if vals[2] ~= nil then
			arg_file_duration = vals[2]
		end

		return true
	end

	return false
end
-------------------------------------------------------------------------------
-- Summary handling helpers
-------------------------------------------------------------------------------
local services =
{
	[80] = 'HTTP',
	[8080] = 'HTTP',
	[443] = 'HTTPs',
	[22] = 'SSH',
	[53] = 'DNS',
	[6666] = 'Sysdig Agent',
	[6667] = 'Sysdig Agent',
	[6443] = 'Sysdig Agent',
	[2379] = 'etcd',
	[22379] = 'etcd',
	[3306] = 'mysql',
	[5432] = 'postgres',
	[6379] = 'redis',
	[5984] = 'couchdb',
	[9880] = 'fluentd',
	[8125] = 'statsd',
	[4730] = 'gearman',
	[50070] = 'hadoop',
	[8020] = 'hadoop',
	[9000] = 'hadoop',
	[60000] = 'hbase',
	[60010] = 'hbase',
	[60020] = 'hbase',
	[60030] = 'hbase',
	[2181] = 'kafka',
	[1978] = 'Kyoto Tycoon',
	[11211] = 'memcached',
	[27017] = 'mongodb',
	[27018] = 'mongodb',
	[27019] = 'mongodb',
	[28017] = 'mongodb',
	[5672] = 'rabbitmq',
	[8087] = 'riak',
	[8098] = 'riak',
	[8983] = 'solr',
	[5555] = 'voltdb'
}

--
-- Populate the protocol table for a crappy application that use a ton of ports
--
for j=9200,9400,1 do services[j] = 'elasticsearch' end

--
-- Create the protocols table by inverting the services table
--
local protocols = {}
for i, v in pairs(services) do
	if protocols[v] == nil then
		protocols[v] = {i}
	else
		protocols[v][#protocols[v] + 1] = i
	end
end

function create_category_basic(excludable, noteworthy, aggregation)
	aggregation = aggregation or 'sum'

	return {
		tot=0, 
		max=0, 
		timeLine={}, 
		excludable=excludable, 
		noteworthy=noteworthy,
		aggregation=aggregation
	}
end

function create_category_table(excludable, noteworthy, aggregation)
	aggregation = aggregation or 'sum'

	return {
		tot=0, 
		max=0, 
		timeLine={}, 
		table={},
		excludable=excludable, 
		noteworthy=noteworthy,
		aggregation=aggregation
	}
end

function reset_summary(s)
	s.procCount = create_category_table(false, false, 'avg')
	s.containerCount = create_category_table(false, false, 'avg')
	s.executedCommands = create_category_basic(false, true)
	s.executedInteractiveCommands = create_category_basic(true, true)
	s.syscallCount = create_category_basic(false, false)
	s.fileCount = create_category_table(true, false)
	s.fileBytes = create_category_basic(false, false)
	s.fileBytesR = create_category_basic(false, false)
	s.fileBytesW = create_category_basic(false, false)
	s.fileCountW = create_category_table(true, false)
	s.sysFileCountW = create_category_table(true, true)
	s.connectionCount = create_category_table(true, false)
	s.netBytes = create_category_basic(false, false)
	s.netBytesR = create_category_basic(false, false)
	s.netBytesW = create_category_basic(false, false)
	s.notifications = create_category_basic(true, true)
	if s.listeningPortCount == nil then
		s.listeningPortCount = create_category_table(true, false, 'avg')
	end
	s.newConnectionsO = create_category_basic(true, false)
	s.newConnectionsI = create_category_basic(true, false)
	s.newConnectionsSsh = create_category_basic(true, true)
	s.newListeningPorts = create_category_basic(true, true)
	s.fileDeletionsCount = create_category_basic(true, true)
	s.newSymLinksCount = create_category_basic(true, true)
	s.forkCount = create_category_basic(true, false)
	s.openErrorCount = create_category_basic(true, false)
	s.connectErrorCount = create_category_basic(true, true)
	s.sudoInvocations = create_category_basic(true, true)
	s.setnsInvocations = create_category_basic(true, true)
	s.signalCount = create_category_basic(true, false)
	s.segfaultCount = create_category_basic(true, true)
	s.over1msFileIoCount = create_category_basic(true, false)
	s.over10msFileIoCount = create_category_basic(true, false)
	s.over100msFileIoCount = create_category_basic(true, true)
	s.appLogCount = create_category_basic(true, false)
	s.appLogCountW = create_category_basic(true, false)
	s.appLogCountE = create_category_basic(true, true)
	s.sysLogCount = create_category_basic(true, false)
	s.sysLogCountW = create_category_basic(true, false)
	s.sysLogCountE = create_category_basic(true, true)
	s.dockerEvtsCount = create_category_basic(true, true)
	-- reset dynamic dockerEvtsCount* categories
	for ccat in pairs(s) do
		prefix = 'dockerEvtsCount'
		if starts_with(ccat, prefix) and ccat ~= prefix then
			s[ccat] = create_category_basic(true, true)
		end
	end
	s.sysReqCountHttp = create_category_basic(true, true)
	s.sysErrCountHttp = create_category_basic(true, true)

	-- creating the protocol categories involves two passes of the services table
	for i, v in pairs(protocols) do
		local ccat = 'protoBytes_' .. i
		s[ccat] = create_category_basic(true, false)
	end
end

function add_summaries(ts_s, ts_ns, dst, src)
	local time = sysdig.make_ts(ts_s, ts_ns)

	for k, v in pairs(src) do
		if dst[k] == nil then
			-- add missing category dynamically
			-- dynamic categories are dockerEvtsCount*
			prefix = 'dockerEvtsCount'
			if starts_with(k, prefix) and k ~= prefix then
				dst[k] = create_category_basic(true, true)
			end
		end

		dst[k].tot = dst[k].tot + v.tot
		if v.tot > dst[k].max then
			dst[k].max = v.tot 
		end
		local tl = dst[k].timeLine
		tl[#tl+1] = {t=time, v=v.tot}

		if v.table ~= nil then
			local dt = dst[k].table
			for tk, tv in pairs(v.table) do
				dt[tk] = tv
			end
		end
	end
end

function generate_subsampled_timeline(src, nsamples, op)
	local res = {}
	local ratio = math.ceil(#src / nsamples)
	local k = 0
	local accumulator = 0
	local etime = src[1].t
	local max = 0
	local tot = 0

	for j = 1,#src,1 do
		k = k + 1
		accumulator = accumulator + src[j].v

		if k >= ratio then
			if op == 'avg' then
				accumulator = accumulator / k
			end

			res[#res+1] = {t=etime, v=accumulator}

			tot = tot + accumulator
			if accumulator > max then
				max = accumulator
			end
			k = 0
			accumulator = 0
			if src[j + 1] ~= nil then
				etime = src[j + 1].t
			end
		end
	end

	return{timeLine=res, tot=tot, max=max}
end

function subsample_timelines(jtable)
	if arg_n_timeline_samples ~= 0 and arg_n_timeline_samples ~= n_samples then
		for k, v in pairs(jtable.metrics) do
			local data = v.data
			st = generate_subsampled_timeline(data.timeLine, 
				arg_n_timeline_samples, 
				data.aggregation)

			v.data.timeLine = st.timeLine
			v.data.max = st.max
		end
	end
end

-------------------------------------------------------------------------------
-- Helpers to dig into the data coming from sysdig
-------------------------------------------------------------------------------
function string.starts(big_str, small_str)
   return string.sub(big_str, 1, string.len(small_str)) == small_str
end

function is_system_dir(filename)
	if string.starts(filename, '/bin/') or
		string.starts(filename, '/sbin/') or
		string.starts(filename, '/boot/') or
		string.starts(filename, '/etc/') or
		string.starts(filename, '/lib') or
		string.starts(filename, '/usr/bin/') or
		string.starts(filename, '/usr/sbin/') or
		string.starts(filename, '/usr/share/') or
		string.starts(filename, '/usr/lib')
	then
		return true
	end

	return false
end

function is_log_file(filename)
	if(string.find(filename, '%.log') or
		string.find(filename, '_log') or
		string.find(filename, '/var/log')) and
		not (string.find(filename, '%.gz') or string.find(filename, '%.tgz'))
	then
		return true
	end

	return false
end

function generate_io_stats(fdname, cnt_cat)
	if fdname == nil then
		return
	end

	if cnt_cat.table[fdname] == nil then
		cnt_cat.table[fdname] = 1
		cnt_cat.tot = cnt_cat.tot + 1
	end
end

function generate_proto_stats(sport, buflen)
	local proto = services[sport]
	if proto ~= nil then
		local catname = 'protoBytes_' .. proto
		ssummary[catname].tot = ssummary[catname].tot + buflen
	end
end

function parse_thread_table_startup()
	local data = {}
	local cnt = 0

	local ttable = sysdig.get_thread_table_barebone(sysdig.get_filter())

	for k, v in pairs(ttable) do
		for kf, vf in pairs(v.fdtable) do
			if vf.is_server then
					data[vf.sport] = 1
			end
		end			
	end

	ssummary.listeningPortCount.tot = 0
	for k, v in pairs(data) do
		ssummary.listeningPortCount.tot = ssummary.listeningPortCount.tot + 1
	end
--print(ssummary.listeningPortCount.tot)
	ssummary.listeningPortCount.table = data
end

function parse_thread_table_interval()
	local data = {}
	local cnt = 0
	local ttable = sysdig.get_thread_table_barebone_nofds(sysdig.get_filter())

	for k, v in pairs(ttable) do
		if v.tid == v.pid then
			data[v.pid] = 1
			cnt = cnt + 1
		end
	end

	ssummary.procCount.tot = cnt
	ssummary.procCount.table = data
end

function parse_container_table()
	local data = {}
	local cnt = 0

	local ctable = sysdig.get_container_table()

	for k, v in pairs(ctable) do
		data[v.id] = v.name
		cnt = cnt + 1
	end

	ssummary.containerCount.tot = cnt
	ssummary.containerCount.table = data
end

function update_docker_cats(evt_type)
	local cat = 'dockerEvtsCount' .. evt_type

	if (ssummary[cat] == nil) then
		ssummary[cat] = create_category_basic(true, true)
	end

	ssummary[cat].tot = ssummary[cat].tot + 1
end

-------------------------------------------------------------------------------
-- Initialization callbacks
-------------------------------------------------------------------------------
function on_init()
	if arg_file_duration == nil then
		return true
	end

	if(sysdig.get_filter() ~= nil and sysdig.get_filter() ~= '') then
		disable_index = true
	end

	sampling_period = arg_file_duration / (n_samples - 1)
	chisel.set_precise_interval_ns(sampling_period)
	percent_update_sample_period = math.floor(n_samples / 100 * 3)
	if percent_update_sample_period < 2 then
		percent_update_sample_period = 1
	end

    reset_summary(gsummary)
    reset_summary(ssummary)

	-- set the following fields on_event()
	fetype = chisel.request_field("evt.type")
	fdir = chisel.request_field("evt.dir")
	frawres = chisel.request_field("evt.rawres")
	ffdcontname = chisel.request_field("fd.containername")
	ffdname = chisel.request_field("fd.name")
	ffdtype = chisel.request_field("fd.type")
	fiswrite = chisel.request_field("evt.is_io_write")
	fisread = chisel.request_field("evt.is_io_read")
	fbuffer = chisel.request_field("evt.buffer")
	fbuflen = chisel.request_field("evt.buflen")
	fsport = chisel.request_field("fd.sport")
	flport = chisel.request_field("fd.lport")
	ftypechar = chisel.request_field("fd.typechar")
	fexe = chisel.request_field("evt.arg.exe")
	fsignal = chisel.request_field("evt.arg.sig")
	flatency = chisel.request_field("evt.latency")
	fsyslogsev = chisel.request_field("syslog.severity")
	finfrasource = chisel.request_field("evt.arg.source")
	finfraname = chisel.request_field("evt.arg.name")
	fpname = chisel.request_field("proc.pname")

	print('{"slices": [')
	return true
end

function on_capture_start()
	if arg_file_duration == nil then
		return true
	end

	if not disable_index then
		local dirname = sysdig.get_evtsource_name() .. '_wd_index'
		local f = io.open(dirname .. '/VERSION', "r")
		if f ~= nil then
			local version = tonumber(f:read "*all")
			f:close()

			if version == index_format_version then
				file_cache_exists = true
				sysdig.end_capture()
			end
		end
	end

	parse_thread_table_startup()
	return true
end

-------------------------------------------------------------------------------
-- Event callback
-------------------------------------------------------------------------------
function on_event()
	if arg_file_duration == nil then
		evtcnt = evtcnt + 1
		return true
	end

	ssummary.syscallCount.tot = ssummary.syscallCount.tot + 1

	local dir = evt.field(fdir)

	if dir ~= nil then
		if dir == '<' then
			local rawres = evt.field(frawres)
			local etype = evt.field(fetype)

			if rawres ~= nil and rawres >= 0 then
				local fdcontname = evt.field(ffdcontname)
				local fdname = evt.field(ffdname)
				local fdtype = evt.field(ffdtype)
				local iswrite = evt.field(fiswrite)
				local isread = evt.field(fisread)

				if iswrite or isread then
					if fdtype == 'file' then
						local buflen = evt.field(fbuflen)
						if buflen == nil then
							buflen = 0
						end
						
						generate_io_stats(fdcontname, ssummary.fileCount)

						if iswrite then
							generate_io_stats(fdcontname, ssummary.fileCountW)
							ssummary.fileBytes.tot = ssummary.fileBytes.tot + buflen
							ssummary.fileBytesW.tot = ssummary.fileBytesW.tot + buflen

							if is_system_dir(fdname) then
								generate_io_stats(fdname, ssummary.sysFileCountW)
							end

							-- log metrics support

							local syslogsev = evt.field(fsyslogsev)
							if syslogsev ~= nil then
								ssummary.sysLogCount.tot = ssummary.sysLogCount.tot + 1
								if syslogsev == 4 then
									ssummary.sysLogCountW.tot = ssummary.sysLogCountW.tot + 1
								elseif syslogsev < 4 then
									ssummary.sysLogCountE.tot = ssummary.sysLogCountE.tot + 1
								end
							elseif is_log_file(fdname) then
								local buf = evt.field(fbuffer)
								local msgs = split(buf, "\n")

								for i, msg in ipairs(msgs) do
									if #msg ~= 0 then
										ssummary.appLogCount.tot = ssummary.appLogCount.tot + 1

										local ls = string.lower(msg)

										if string.find(ls, "warn") then
											ssummary.appLogCountW.tot = ssummary.appLogCountW.tot + 1
										elseif string.find(ls, "error") or 
											string.find(ls, "critic") or 
											string.find(ls, "emergency") or 
											string.find(ls, "alert") then
												ssummary.appLogCountE.tot = ssummary.appLogCountE.tot + 1
										end
									end
								end
							end
						elseif isread then
							ssummary.fileBytes.tot = ssummary.fileBytes.tot + buflen
							ssummary.fileBytesR.tot = ssummary.fileBytesR.tot + buflen
						end

						local latency = evt.field(flatency)
						if latency ~= nil and not string.starts(fdname, '/dev/') then
							if latency > 100000000 then
								ssummary.over100msFileIoCount.tot = ssummary.over100msFileIoCount.tot + 1
							end
							if latency > 10000000 then
								ssummary.over10msFileIoCount.tot = ssummary.over10msFileIoCount.tot + 1
							end
							if latency > 1000000 then
								ssummary.over1msFileIoCount.tot = ssummary.over1msFileIoCount.tot + 1
							end
						end	
					elseif fdtype == 'ipv4' or fdtype == 'ipv6' then
						local buflen = evt.field(fbuflen)
						if buflen == nil then
							buflen = 0
						end

						generate_io_stats(fdcontname, ssummary.connectionCount)

						if iswrite then
							ssummary.netBytes.tot = ssummary.netBytes.tot + buflen
							ssummary.netBytesW.tot = ssummary.netBytesW.tot + buflen
						elseif isread then
							ssummary.netBytes.tot = ssummary.netBytes.tot + buflen
							ssummary.netBytesR.tot = ssummary.netBytesR.tot + buflen
						end

						local sport = evt.field(fsport)
						if sport ~= nil then
							generate_proto_stats(sport, buflen)
						end

						local buf = evt.field(fbuffer)
						if string.starts(buf, 'HTTP/') then
							ssummary.sysReqCountHttp.tot = ssummary.sysReqCountHttp.tot + 1
							
							local parts = split(buf, ' ')
							if tonumber(parts[2]) ~= 200 then
								ssummary.sysErrCountHttp.tot = ssummary.sysErrCountHttp.tot + 1
							end
						end

					elseif fdtype == 'unix' then
						if iswrite then
							-- apps can write to syslog using unix pipes
							local syslogsev = evt.field(fsyslogsev)
							if syslogsev ~= nil then
								ssummary.sysLogCount.tot = ssummary.sysLogCount.tot + 1
								if syslogsev == 4 then
									ssummary.sysLogCountW.tot = ssummary.sysLogCountW.tot + 1
								elseif syslogsev < 4 then
									ssummary.sysLogCountE.tot = ssummary.sysLogCountE.tot + 1
								end
							end
						end
					end
				elseif etype == 'execve' then
					ssummary.executedCommands.tot = ssummary.executedCommands.tot + 1
					local pname = evt.field(fpname)
					if pname ~= nil then
						if string.find(pname, 'bash') then
							ssummary.executedInteractiveCommands.tot = ssummary.executedInteractiveCommands.tot + 1
						end
					end

					local exe = evt.field(fexe)
					if exe == 'sudo' then
						ssummary.sudoInvocations.tot = ssummary.sudoInvocations.tot + 1
					end
				elseif etype == 'bind' then
					local sport = evt.field(fsport)
					if sport ~= nil then
						generate_io_stats(sport, ssummary.listeningPortCount)
						ssummary.newListeningPorts.tot = ssummary.newListeningPorts.tot + 1
					end
				elseif etype == 'connect' then
					local sport = evt.field(fsport)
					if sport ~= nil then
						ssummary.newConnectionsO.tot = ssummary.newConnectionsO.tot + 1
						if sport == 22 then
							ssummary.newConnectionsSsh.tot = ssummary.newConnectionsSsh.tot + 1
						end
					end
				elseif etype == 'accept' then
					local sport = evt.field(fsport)
					if sport ~= nil then
						ssummary.newConnectionsI.tot = ssummary.newConnectionsI.tot + 1
						if sport == 22 then
							ssummary.newConnectionsSsh.tot = ssummary.newConnectionsSsh.tot + 1
						end
					end
				elseif etype == 'unlink' or etype == 'unlinkat' then
					ssummary.fileDeletionsCount.tot = ssummary.fileDeletionsCount.tot + 1
				elseif etype == 'symlink' or etype == 'symlinkat' then
					ssummary.newSymLinksCount.tot = ssummary.newSymLinksCount.tot + 1
				elseif etype == 'clone' or etype == 'fork' then
					if rawres > 0 then
						ssummary.forkCount.tot = ssummary.forkCount.tot + 1
					end
				elseif etype == 'setns' then
					ssummary.setnsInvocations.tot = ssummary.setnsInvocations.tot + 1
				end
			elseif etype == 'connect' then
				local sport = evt.field(fsport)
				if sport ~= nil then
					ssummary.newConnectionsO.tot = ssummary.newConnectionsO.tot + 1
					if sport == 22 then
						ssummary.newConnectionsSsh.tot = ssummary.newConnectionsSsh.tot + 1
					end
				end

				if rawres ~= -115 then
					local fdtype = evt.field(ffdtype)
					if fdtype == 'ipv4' or fdtype == 'ipv6' then
						ssummary.connectErrorCount.tot = ssummary.connectErrorCount.tot + 1
					end
				end
			elseif etype == 'accept' then
				local sport = evt.field(fsport)
				if sport ~= nil then
					ssummary.newConnectionsI.tot = ssummary.newConnectionsI.tot + 1
					if sport == 22 then
						ssummary.newConnectionsSsh.tot = ssummary.newConnectionsSsh.tot + 1
					end
				end
			elseif etype == 'open' then
				ssummary.openErrorCount.tot = ssummary.openErrorCount.tot + 1
			end
		else	
			local etype = evt.field(fetype)
			if etype == 'close' then
				local sport = evt.field(fsport)
				if sport ~= nil then
					local typechar = evt.field(ftypechar)
					if typechar == '2' then
						if ssummary.listeningPortCount.table[sport] ~= nil then
							ssummary.listeningPortCount.table[sport] = nil
							ssummary.listeningPortCount.tot = ssummary.listeningPortCount.tot - 1
						end
					end
				end
			elseif etype == 'signaldeliver' then
				ssummary.signalCount.tot = ssummary.signalCount.tot + 1
				local signal = evt.field(fsignal)
				if signal == 'SIGSEGV' then
					ssummary.segfaultCount.tot = ssummary.segfaultCount.tot + 1
				end
			elseif etype == 'notification' then
				ssummary.notifications.tot = ssummary.notifications.tot + 1
			elseif etype == 'infra' then
				local infrasource = evt.field(finfrasource)
				if infrasource == 'docker' then
					ssummary.dockerEvtsCount.tot = ssummary.dockerEvtsCount.tot + 1

					local infraname = evt.field(finfraname)
					update_docker_cats(infraname)
				end
			end
		end
	end

	return true
end

-------------------------------------------------------------------------------
-- Periodic timeout callback
-------------------------------------------------------------------------------
function on_interval(ts_s, ts_ns, delta)
	parse_thread_table_interval()
	parse_container_table()

--print(json.encode(ssummary.connectionCount, { indent = true }))
	add_summaries(ts_s, ts_ns, gsummary, ssummary)
	reset_summary(ssummary)

	if nintervals % percent_update_sample_period == 0 then
		local progress = sysdig.get_read_progress()
		if progress == 100 then
			progress = 99.99
		end
		print('{"progress": ' .. progress .. ' },')
		io.flush(stdout)
	end

	nintervals = nintervals + 1

	return true
end

-------------------------------------------------------------------------------
-- End of capture output generation
-------------------------------------------------------------------------------
function update_table_count(cat)
	if cat.table ~= nil then
		local cnt = 0
		for tk, tv in pairs(cat.table) do
			cnt = cnt + 1
		end

		cat.tot = cnt
		cat.table = nil
	end
end

function update_table_counts()
	for k, v in pairs(gsummary) do
		update_table_count(v)
	end
end

function should_include(category)
	if category.excludable then
		if category.tot ~= 0 then
			return true
		else
			return false
		end
	else
		return true
	end
end

function get_category_table(include_network_apps, include_security, include_performance, include_logs, include_infrastructure)
	local res = {
		{id='general', name='General'},
		{id='file', name='File'},
		{id='network', name='Network'},
	}

	if include_network_apps then
		res[#res+1] = {id='napps', name='Network Apps'}
	end
	
	if include_security then
		res[#res+1] = {id='security', name='Security'}
	end
	
	if include_performance then
		res[#res+1] = {id='performance', name='Performance'}
	end

	if include_logs then
		res[#res+1] = {id='logs', name='Logs'}
	end

	if include_infrastructure then
		res[#res+1] = {id='infrastructure', name='Infrastructure'}
	end

	return res
end

function build_output(captureDuration)
	local ctable = copytable(gsummary.containerCount.table)
	local res = {}
	local has_cat_logs = false;
	local has_cat_infrastructure = false;
	local has_cat_netapps = false;
	
	local jtable = {
		info={
			IndexFormatVersion=index_format_version, 
			containers=ctable,
			durationNs=captureDuration,
			startTs = sysdig.get_firstevent_ts(),
			endTs = sysdig.get_lastevent_ts()
		},
		metrics=res}
	local filter = sysdig.get_filter()

	update_table_counts()

	if should_include(gsummary.notifications) then
		res[#res+1] = {
			name = 'Sysdig Secure Notifications',
			desc = 'Sysdig Secure notifications. Sysdig secure inserts a "notification" event in the capture stream each time a policy triggers. This metric counts the notifications. Chart it over time to compare the other metrics with the point in time where policies were triggered.',
			category = 'general',
			targetView = 'notifications',
			drillDownKey = 'NONE',
			data = gsummary.notifications
		}
	end

	if should_include(gsummary.procCount) then
		res[#res+1] = {
			name = 'Running Processes',
			desc = 'Total number of processes that were running during the capture',
			category = 'general',
			targetView = 'procs',
			drillDownKey = '',
			data = gsummary.procCount
		}
	end

	if(not string.find(filter, 'container') and should_include(gsummary.containerCount)) then
		res[#res+1] = {
			name = 'Running Containers',
			desc = 'Total number of containers that were running during the capture',
			category = 'general',
			targetView = 'containers',
			drillDownKey = '',
			data = gsummary.containerCount
		}
	end

	if(should_include(gsummary.syscallCount)) then
		res[#res+1] = {
			name = 'System Calls',
			desc = 'Number of system calls performed by any process/container in the system',
			category = 'general',
			targetView = 'syscalls',
			drillDownKey = '',
			data = gsummary.syscallCount
		}
	end

	if should_include(gsummary.fileBytes) then
		res[#res+1] = {
			name = 'File Bytes In+Out',
			desc = 'Amount of bytes read from or written to the file system',
			category = 'file',
			targetView = 'files',
			drillDownKey = 'fd.directory',
			targetViewSortingCol = 2,
			data = gsummary.fileBytes
		}
	end

	if should_include(gsummary.fileBytesR) then
		res[#res+1] = {
			name = 'File Bytes In',
			desc = 'Amount of bytes read from the file system',
			category = 'file',
			targetView = 'files',
			drillDownKey = 'fd.directory',
			targetViewSortingCol = 0,
			data = gsummary.fileBytesR
		}
	end

	if should_include(gsummary.fileBytesW) then
		res[#res+1] = {
			name = 'File Bytes Out',
			desc = 'Amount of bytes written to the file system',
			category = 'file',
			targetView = 'files',
			drillDownKey = 'fd.directory',
			targetViewSortingCol = 1,
			data = gsummary.fileBytesW
		}
	end

	if should_include(gsummary.fileCount) then
		res[#res+1] = {
			name = 'Accessed Files',
			desc = 'Number of files that have been accessed during the capture',
			category = 'file',
			targetView = 'files',
			targetViewFilter = 'evt.is_io_read=true',
			drillDownKey = 'fd.directory',
			targetViewSortingCol = 2,
			data = gsummary.fileCount
		}
	end

	if should_include(gsummary.fileCountW) then
		res[#res+1] = {
			name = 'Modified Files',
			desc = 'Number of files that have been received writes during the capture',
			category = 'file',
			targetView = 'files',
			drillDownKey = 'fd.directory',
			targetViewSortingCol = 1,
			targetViewFilter = 'evt.is_io_write=true',
			data = gsummary.fileCountW
		}
	end

	if should_include(gsummary.netBytes) then
		res[#res+1] = {
			name = 'Net Bytes In+Out',
			desc = 'Amount of bytes read from or written to the network',
			category = 'network',
			targetView = 'sports',
			drillDownKey = 'fd.directory',
			targetViewSortingCol = 4,
			data = gsummary.netBytes
		}
	end

	if should_include(gsummary.netBytesR) then
		res[#res+1] = {
			name = 'Net Bytes In',
			desc = 'Amount of bytes read from the network',
			category = 'network',
			targetView = 'sports',
			drillDownKey = 'fd.sport',
			targetViewSortingCol = 2,
			data = gsummary.netBytesR
		}
	end

	if should_include(gsummary.netBytesW) then
		res[#res+1] = {
			name = 'Net Bytes Out',
			desc = 'Amount of bytes written to the network',
			category = 'network',
			targetView = 'sports',
			drillDownKey = 'fd.sport',
			targetViewSortingCol = 3,
			data = gsummary.netBytesW
		}
	end

	if should_include(gsummary.connectionCount) then
		res[#res+1] = {
			name = 'Active Network Connections',
			desc = 'Number of network connections that have been accessed during the capture',
			category = 'network',
			targetView = 'connections',
			targetViewFilter = 'evt.is_io=true',
			drillDownKey = 'fd.sport',
			targetViewSortingCol = 8,
			data = gsummary.connectionCount
		}
	end

	if should_include(gsummary.listeningPortCount) then
		res[#res+1] = {
			name = 'Listening Ports',
			desc = 'Number of open ports on this system',
			category = 'network',
			targetView = 'port_bindings',
			drillDownKey = 'fd.sport',
			data = gsummary.listeningPortCount
		}
	end

	if should_include(gsummary.newListeningPorts) then
		res[#res+1] = {
			name = 'New Listening Ports',
			desc = 'Number of open ports that have been added during the observation interval',
			category = 'network',
			targetView = 'port_bindings',
			drillDownKey = 'fd.sport',
			data = gsummary.newListeningPorts
		}
	end

	if should_include(gsummary.newConnectionsO) then
		res[#res+1] = {
			name = 'New Outbound Connections',
			desc = 'New client network connections',
			category = 'network',
			targetView = 'dig',
			targetViewTitle = 'Connect events',
			targetViewFilter = 'evt.type=connect and evt.dir=< and fd.sport exists',
			drillDownKey = 'NONE',
			data = gsummary.newConnectionsO
		}
	end

	if should_include(gsummary.newConnectionsI) then
		res[#res+1] = {
			name = 'New Inbound Connections',
			desc = 'New server network connections',
			category = 'network',
			targetView = 'dig',
			targetViewTitle = 'Connect events',
			targetViewFilter = 'evt.type=accept and evt.dir=< and fd.sport exists',
			drillDownKey = '',
			data = gsummary.newConnectionsI
		}
	end

	if should_include(gsummary.executedCommands) then
		res[#res+1] = {
			name = 'Executed Commands',
			desc = 'Number of new programs that have been executed during the observed interval',
			category = 'security',
			targetView = 'spy_users_wsysdig',
			drillDownKey = '',
			data = gsummary.executedCommands
		}
	end

	if should_include(gsummary.executedInteractiveCommands) then
		res[#res+1] = {
			name = 'Executed Interactive Commands',
			desc = 'Number of new programs that have been executed from a shell during the observed interval',
			category = 'security',
			targetView = 'spy_users_wsysdig',
			targetViewFilter = 'proc.pname=bash',
			drillDownKey = 'NONE',
			data = gsummary.executedInteractiveCommands
		}
	end

	if should_include(gsummary.newSymLinksCount) then
		res[#res+1] = {
			name = 'New Symlinks',
			desc = 'Number of new symbolic links that were created',
			category = 'security',
			targetView = 'dig',
			targetViewTitle = 'Symlink creations',
			targetViewFilter = '(evt.type=symlink or evt.type=symlinkat) and evt.dir=< and evt.failed = false',
			drillDownKey = 'NONE',
			data = gsummary.newSymLinksCount
		}
	end

	if should_include(gsummary.sysFileCountW) then
		res[#res+1] = {
			name = 'Modified System Files',
			desc = 'Number of files that have been accessed during the capture',
			category = 'security',
			targetViewSortingCol = 1,
			targetView = 'files',
			targetViewFilter = 'evt.is_io_write=true',
			drillDownKey = 'NONE',
			data = gsummary.sysFileCountW
		}
	end

	if should_include(gsummary.sudoInvocations) then
		res[#res+1] = {
			name = 'Sudo Invocations',
			desc = 'Number of times the sudo program has been called',
			category = 'security',
			targetView = 'dig',
			targetViewTitle = 'Sudo executions',
			targetViewFilter = 'evt.type=execve and evt.arg.exe=sudo',
			drillDownKey = 'NONE',
			data = gsummary.sudoInvocations
		}
	end

	if should_include(gsummary.setnsInvocations) then
		res[#res+1] = {
			name = 'Setns Invocations',
			desc = 'Number of times the setns system call has been called. Setns is typically used to "enter" in another container',
			category = 'security',
			targetView = 'dig',
			targetViewTitle = 'Setns executions',
			targetViewFilter = 'evt.type=setns',
			drillDownKey = 'NONE',
			data = gsummary.setnsInvocations
		}
	end

	if should_include(gsummary.newConnectionsSsh) then
		res[#res+1] = {
			name = 'New SSH Connections',
			desc = 'Client or server connections',
			category = 'security',
			targetView = 'dig',
			targetViewTitle = 'Connect events',
			targetViewFilter = '(evt.type=accept or evt.type=connect) and evt.dir=< and fd.sport=22',
			drillDownKey = '',
			data = gsummary.newConnectionsSsh
		}
	end

	if should_include(gsummary.fileDeletionsCount) then
		res[#res+1] = {
			name = 'Deleted Files',
			desc = 'Number of files that were deleted',
			category = 'security',
			targetView = 'dig',
			targetViewTitle = 'File deletions',
			targetViewFilter = 'evt.type=unlink or evt.type=unlinkat',
			drillDownKey = 'NONE',
			data = gsummary.fileDeletionsCount
		}
	end
	
	if should_include(gsummary.sysReqCountHttp) then
		res[#res+1] = {
			name = 'HTTP Requests',
			desc = 'Number of HTTP requests',
			category = 'performance',
			targetView = 'echo',
			targetViewTitle = 'HTTP responses',
			targetViewFilter = '(fd.type=ipv4 or fd.type=ipv6) and evt.buffer contains "HTTP/"',
			drillDownKey = 'fd.directory',
			data = gsummary.sysReqCountHttp
		}
	end

	if should_include(gsummary.sysErrCountHttp) then
		res[#res+1] = {
			name = 'HTTP Errors',
			desc = 'Number of HTTP responses with code different from 400',
			category = 'performance',
			targetView = 'echo',
			targetViewTitle = 'HTTP responses',
			targetViewFilter = '(fd.type=ipv4 or fd.type=ipv6) and evt.arg.data startswith "HTTP/" and not evt.arg.data contains "200"',
			drillDownKey = 'fd.directory',
			data = gsummary.sysErrCountHttp
		}
	end

	if should_include(gsummary.openErrorCount) then
		res[#res+1] = {
			name = 'File Open Errors',
			desc = 'Count of failed file opens',
			category = 'performance',
			targetView = 'dig',
			targetViewTitle = 'Failed open() calls',
			targetViewFilter = 'evt.type=open and evt.rawres<0',
			drillDownKey = 'fd.directory',
			data = gsummary.openErrorCount
		}
	end
	
	if should_include(gsummary.forkCount) then
		res[#res+1] = {
			name = 'Fork Count',
			desc = 'Count of processes and threads that have been created',
			category = 'performance',
			targetView = 'dig',
			targetViewTitle = 'Clone executions',
			targetViewFilter = 'evt.type=clone and evt.rawres=0',
			drillDownKey = 'NONE',
			data = gsummary.forkCount
		}
	end

	if should_include(gsummary.connectErrorCount) then
		res[#res+1] = {
			name = 'Failed Connection Attempts',
			desc = 'Count of failed network connect calls',
			category = 'performance',
			targetView = 'dig',
			targetViewTitle = 'Failed connect() calls',
			targetViewFilter = 'evt.type=connect and (fd.type=ipv4 or fd.type=ipv6) and evt.rawres<0 and evt.res!=EINPROGRESS',
			drillDownKey = 'NONE',
			data = gsummary.connectErrorCount
		}
	end

	if should_include(gsummary.signalCount) then
		res[#res+1] = {
			name = 'Received Signals',
			desc = 'Number of unix signals that have been received by the processes on the system',
			category = 'performance',
			targetView = 'dig',
			targetViewTitle = 'Received signals',
			targetViewFilter = 'evt.type=signaldeliver',
			drillDownKey = 'NONE',
			data = gsummary.signalCount
		}
	end

	if should_include(gsummary.segfaultCount) then
		res[#res+1] = {
			name = 'Segmentation Faults',
			desc = 'Number of process segfaults',
			category = 'performance',
			targetView = 'dig',
			targetViewTitle = 'List of segfault events',
			targetViewFilter = 'evt.type=signaldeliver and evt.arg.sig=SIGSEV',
			drillDownKey = 'NONE',
			data = gsummary.segfaultCount
		}
	end

	if should_include(gsummary.over1msFileIoCount) then
		res[#res+1] = {
			name = 'Slow File I/O calls (1ms+)',
			desc = 'Number of file read or write calls that took more than 1ms to return',
			category = 'performance',
			targetView = 'slow_io',
			targetViewSortingCol = 1,
			drillDownKey = 'NONE',
			data = gsummary.over1msFileIoCount
		}
	end

	if should_include(gsummary.over10msFileIoCount) then
		res[#res+1] = {
			name = 'Slow File I/O calls (10ms+)',
			desc = 'Number of file read or write calls that took more than 10ms to return',
			category = 'performance',
			targetView = 'slow_io',
			targetViewSortingCol = 1,
			drillDownKey = 'NONE',
			data = gsummary.over10msFileIoCount
		}
	end

	if should_include(gsummary.over100msFileIoCount) then
		res[#res+1] = {
			name = 'Slow File I/O calls (100ms+)',
			desc = 'Number of file read or write calls that took more than 100ms to return',
			category = 'performance',
			targetView = 'slow_io',
			targetViewSortingCol = 1,
			drillDownKey = 'NONE',
			data = gsummary.over100msFileIoCount
		}
	end

	if should_include(gsummary.appLogCount) then
		res[#res+1] = {
			name = 'App Log Messages',
			desc = 'Number of wrtites to application log files',
			category = 'logs',
			targetView = 'echo',
			targetViewTitle = 'Application Log Messages',
			targetViewFilter = '((fd.name contains .log or fd.name contains _log or fd.name contains /var/log) and not (fd.name contains .gz or fd.name contains .tgz)) and evt.is_io_write=true',
			drillDownKey = 'NONE',
			data = gsummary.appLogCount
		}
		has_cat_logs = true
	end

	if should_include(gsummary.appLogCountW) then
		res[#res+1] = {
			name = 'App Log Warning Messages',
			desc = 'Number of writes to application log files containing the word "warning"',
			category = 'logs',
			targetView = 'echo',
			targetViewTitle = 'Warning Application Log Messages',
			targetViewFilter = '((fd.name contains .log or fd.name contains _log or fd.name contains /var/log) and not (fd.name contains .gz or fd.name icontains .tgz)) and evt.is_io_write=true and evt.arg.data icontains warn',
			drillDownKey = 'NONE',
			data = gsummary.appLogCountW
		}
		has_cat_logs = true
	end

	if should_include(gsummary.appLogCountE) then
		res[#res+1] = {
			name = 'App Log Error Messages',
			desc = 'Number of writes to application log files containing the word "error"',
			category = 'logs',
			targetView = 'echo',
			targetViewTitle = 'Error Application Log Messages',
			targetViewFilter = '((fd.name contains .log or fd.name contains _log or fd.name contains /var/log) and not (fd.name contains .gz or fd.name contains .tgz)) and evt.is_io_write=true and (evt.arg.data icontains error or evt.arg.data icontains critic or evt.arg.data icontains emergency or evt.arg.data icontains alert)',
			drillDownKey = 'NONE',
			data = gsummary.appLogCountE
		}
		has_cat_logs = true
	end

	if should_include(gsummary.sysLogCount) then
		res[#res+1] = {
			name = 'Syslog Messages',
			desc = 'Number of entries written to syslog',
			category = 'logs',
			targetView = 'spy_syslog',
			targetViewTitle = 'Syslog Messages',
			drillDownKey = 'NONE',
			data = gsummary.sysLogCount
		}
		has_cat_logs = true
	end

	if should_include(gsummary.sysLogCountW) then
		res[#res+1] = {
			name = 'Syslog Warning Messages',
			desc = 'Number of entries with severity WARNING written to syslog',
			category = 'logs',
			targetView = 'spy_syslog',
			targetViewTitle = 'Syslog Messages',
			targetViewFilter = 'syslog.severity=4',
			drillDownKey = 'NONE',
			data = gsummary.sysLogCountW
		}
		has_cat_logs = true
	end

	if should_include(gsummary.sysLogCountE) then
		res[#res+1] = {
			name = 'Syslog Error Messages',
			desc = 'Number of entries with severity ERROR or lower written to syslog',
			category = 'logs',
			targetView = 'spy_syslog',
			targetViewTitle = 'Syslog Messages',
			targetViewFilter = 'syslog.severity<4',
			drillDownKey = 'NONE',
			data = gsummary.sysLogCountE
		}
		has_cat_logs = true
	end

	if should_include(gsummary.dockerEvtsCount) then
		res[#res+1] = {
			name = 'Docker Events',
			desc = 'Total number of events generated by docker activity',
			category = 'infrastructure',
			targetView = 'docker_events',
			drillDownKey = 'NONE',
			data = gsummary.dockerEvtsCount
		}
		has_cat_infrastructure = true
	end

	-- evaluate dynamic dockerEvtsCount* categories
	prefix = 'dockerEvtsCount'
	dockerEvtsCountEvents = {}
	for ccat in pairs(gsummary) do
		if starts_with(ccat, prefix) and ccat ~= prefix then
			if should_include(gsummary[ccat]) then
				ccat_name = ccat:sub(#prefix + 1)
				dockerEvtsCountEvents[ccat] = {
					name = ccat_name .. ' Events',
					desc = 'Total number of docker events of type ' .. ccat_name,
					category = 'infrastructure',
					targetView = 'docker_events',
					targetViewFilter = 'evt.arg.name="' .. ccat_name .. '"' ,
					drillDownKey = 'NONE',
					data = gsummary[ccat]
				}
				has_cat_infrastructure = true
			end
		end
	end
	-- sort categories to make sure the final list is "stable"
	table.sort(dockerEvtsCountEvents, function (a, b) return a.name - b.name end)
	for i, v in pairs(dockerEvtsCountEvents) do
		res[#res+1] = v
	end

	for i, v in pairs(protocols) do
		local ccat = 'protoBytes_' .. i
		if should_include(gsummary[ccat]) then
			local flt = ''
			for ii, vv in pairs(v) do
				flt = flt .. ('fd.sport=' .. vv .. ' or ')
			end
			flt = string.sub(flt, 0, #flt - 4)

			res[#res+1] = {
				name = i .. ' Bytes',
				desc = 'Total number of network bytes generated by the ' .. i .. ' protocol',
				category = 'napps',
				targetView = 'connections',
				targetViewFilter = flt,
				drillDownKey = 'NONE',
				data = gsummary[ccat]
			}

			has_cat_netapps = true
		end
	end

	jtable.info.categories = get_category_table(has_cat_netapps, true, true, has_cat_logs, has_cat_infrastructure)

	return jtable
end

function load_index(dirname)
	local f = io.open(dirname .. '/summary.json', "r")
	if f == nil then
		return nil
	end

	local res = f:read("*all")
	f:close()

	return res
end

-- Callback called by the engine at the end of the capture
function on_capture_end(ts_s, ts_ns, delta)
	if arg_file_duration == nil then
		sysdig.run_sysdig('-r "' .. sysdig.get_evtsource_name() .. 
			'" -c wsysdig_summary ' .. arg_n_timeline_samples .. ',' .. delta .. ' ' ..
			sysdig.get_filter())
		return true
	end

	local sstr = ''
	local dirname = sysdig.get_evtsource_name() .. '_wd_index'

	if file_cache_exists and not disable_index then
		sstr = load_index(dirname)
		if sstr == nil then
			print('{"progress": 100, "error": "can\'t read the trace file index" }')
			print(']}')
			return false
		end

		jtable = json.decode(sstr)
		subsample_timelines(jtable)
		sstr = json.encode(jtable, { indent = true })
	else
		add_summaries(ts_s, ts_ns, gsummary, ssummary)
		jtable = build_output(delta)
		sstr = json.encode(jtable, { indent = true })

		if not disable_index then
			os.execute('rm -fr ' .. dirname .. " 2> /dev/null")
			os.execute('rmdir ' .. dirname .. " 2> nul")
			os.execute('mkdir ' .. dirname .. " 2> /dev/null")
			os.execute('md ' .. dirname .. " 2> nul")

			-- Save the data
			local f = io.open(dirname .. '/summary.json', "w")
			if f == nil then
				print('{"progress": 100, "error": "can\'t create the trace file index" }')
				print(']}')
				return false
			end

			f:write(sstr)
			f:close()

			-- Save the index version
			local fv = io.open(dirname .. '/VERSION', "w")
			if fv == nil then
				print('{"progress": 100, "error": "can\'t create the trace file index" }')
				print(']}')
				return false
			end

			fv:write(index_format_version)
			fv:close()
		end

		subsample_timelines(jtable)
		sstr = json.encode(jtable, { indent = true })
	end

	print('{"progress": 100, "data": '.. sstr ..'}')
	print(']}')

	return true
end
