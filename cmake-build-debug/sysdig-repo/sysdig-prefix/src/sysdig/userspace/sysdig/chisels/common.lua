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

--[[
This file contains a bunch of functions that are helpful in multiple scripts
]]--

--[[
Serialize the content of a table into a tring
]]--
function st(val, name, skipnewlines, depth)
	skipnewlines = skipnewlines or false
	depth = depth or 0

	local tmp = string.rep(" ", depth)

	if name then tmp = tmp .. name .. " = " end

	if type(val) == "table" then
		tmp = tmp .. "{" .. (not skipnewlines and "\n" or "")

		for k, v in pairs(val) do
			tmp =  tmp .. st(v, k, skipnewlines, depth + 1) .. "," .. (not skipnewlines and "\n" or "")
		end

		tmp = tmp .. string.rep(" ", depth) .. "}"
	elseif type(val) == "number" then
		tmp = tmp .. tostring(val)
	elseif type(val) == "string" then
		tmp = tmp .. string.format("%q", val)
	elseif type(val) == "boolean" then
		tmp = tmp .. (val and "true" or "false")
	else
		tmp = tmp .. "\"[inserializeable datatype:" .. type(val) .. "]\""
	end

	return tmp
end

--[[
Extends a string to newlen with spaces
]]--
function extend_string(s, newlen)
	if #s < newlen then
        local ccs = "                                                                                                                                                                       "
		s = s .. string.sub(ccs, 0, newlen - #s)
		return s
	else
		if newlen > 0 then
			return (string.sub(s, 0, newlen - 1) .. " ")
		else
			return ""
		end
	end
end

--[[
Basic string split.
]]--
function split(s, delimiter)
	local result = {}
	
	for match in (s..delimiter):gmatch("(.-)"..delimiter) do
		table.insert(result, match)
	end
	return result
end

--[[
Substring matching.
]]--
function starts_with(str, prefix)
	return prefix == "" or str:sub(1, #prefix) == prefix
end

function ends_with(str, suffix)
	return suffix == "" or str:sub(-#suffix) == suffix
end

--[[
convert a number into a byte representation.
E.g. 1230 becomes 1.23K
]]--
function format_bytes(val)
	if val > (1024 * 1024 * 1024 * 1024 * 1024) then
		return string.format("%.2fP", val / (1024 * 1024 * 1024 * 1024 * 1024))
	elseif val > (1024 * 1024 * 1024 * 1024) then
		return string.format("%.2fT", val / (1024 * 1024 * 1024 * 1024))
	elseif val > (1024 * 1024 * 1024) then
		return string.format("%.2fG", val / (1024 * 1024 * 1024))
	elseif val > (1024 * 1024) then
		return string.format("%.2fM", val / (1024 * 1024))
	elseif val > 1024 then
		return string.format("%.2fKB", val / (1024))
	else
		return string.format("%dB", val)
	end
end

--[[
convert a nanosecond time interval into a s.ns representation.
E.g. 1100000000 becomes 1.1s
]]--
ONE_S_IN_NS=1000000000
ONE_MS_IN_NS=1000000
ONE_US_IN_NS=1000

function format_time_interval(val)
	if val >= (ONE_S_IN_NS) then
		return string.format("%u.%02us", math.floor(val / ONE_S_IN_NS), (val % ONE_S_IN_NS) / 10000000)
	elseif val >= (ONE_S_IN_NS / 100) then
		return string.format("%ums", math.floor(val / (ONE_S_IN_NS / 1000)))
	elseif val >= (ONE_S_IN_NS / 1000) then
		return string.format("%u.%02ums", math.floor(val / (ONE_S_IN_NS / 1000)), (val % ONE_MS_IN_NS) / 10000)
	elseif val >= (ONE_S_IN_NS / 100000) then
		return string.format("%uus", math.floor(val / (ONE_S_IN_NS / 1000000)))
	elseif val >= (ONE_S_IN_NS / 1000000) then
		return string.format("%u.%02uus", math.floor(val / (ONE_S_IN_NS / 1000000)), (val % ONE_US_IN_NS) / 10)
	else
		return string.format("%uns", val)
	end
end

--[[
extract the top num entries from the table t, after sorting them based on the entry value using the function order()
]]--
function pairs_top_by_val(t, num, order)
	local keys = {}

	for k in pairs(t) do keys[#keys+1] = k end

	table.sort(keys, function(a,b) return order(t, a, b) end)

	local i = 0
	return function()
		i = i + 1
		if (num == 0 or i <= num) and keys[i] then
			return keys[i], t[keys[i]]
		end
	end
end

--[[
Timestamp <-> string conversion
]]--
function ts_to_str(tshi, tslo)
	return string.format("%u%.9u", tshi, tslo)
end

--[[
Pick a key-value table and render it to the console in sorted top format
]]--
json = require ("dkjson")

function print_sorted_table(stable, ts_s, ts_ns, timedelta, viz_info)
	local sorted_grtable = pairs_top_by_val(stable, viz_info.top_number, function(t,a,b) return t[b] < t[a] end)

	if viz_info.output_format == "json" then
		local jdata = {}
		local j = 1
		
		for k,v in sorted_grtable do
			local vals = split(k, "\001\001")
			vals[#vals + 1] = v
			jdata[j] = vals
			j = j + 1
		end
			
		local jinfo = {}
		
		for i, keyname in ipairs(viz_info.key_fld) do
			jinfo[i] = {name = keyname, desc = viz_info.key_desc[i], is_key = true}
		end
		jinfo[3] = {name = viz_info.value_fld, desc = viz_info.value_desc, is_key = false}

		local res = {ts = sysdig.make_ts(ts_s, ts_ns), data = jdata, info = jinfo}
			
		local str = json.encode(res, { indent = true })
		print(str)
	else
		-- Same size to extend each string
		local EXTEND_STRING_SIZE = 20
		local header = extend_string(viz_info.value_desc, EXTEND_STRING_SIZE)
		
		for i, fldname in ipairs(viz_info.key_desc) do
			header = header .. extend_string(fldname, EXTEND_STRING_SIZE)
		end
		
		print(header)
		print("--------------------------------------------------------------------------------")

		for k,v in sorted_grtable do
			local keystr = ""
			
			local singlekeys = split(k, "\001\001")

			for i, singlekey in ipairs(singlekeys) do
				if i < #singlekeys then
					keystr = keystr .. extend_string(string.sub(singlekey, 0, EXTEND_STRING_SIZE), EXTEND_STRING_SIZE)
				else
					keystr = keystr .. singlekey
				end
			end

			if viz_info.value_units == "none" then
				print(extend_string(tostring(v), EXTEND_STRING_SIZE) .. keystr)
			elseif viz_info.value_units == "bytes" then
				print(extend_string(format_bytes(v), EXTEND_STRING_SIZE) .. keystr)
			elseif viz_info.value_units == "time" then
				print(extend_string(format_time_interval(v), EXTEND_STRING_SIZE) .. keystr)
			elseif viz_info.value_units == "timepct" then
				if timedelta > 0 then
					pctstr = string.format("%.2f%%", v / timedelta * 100)
				else
					pctstr = "0.00%"
				end

				print(extend_string(pctstr, EXTEND_STRING_SIZE) .. keystr)	
			end
		end
	end
end

--[[
Try to convert user input to a number using tonumber(). If tonumber() returns
'nil', print an error message to the user and exit, otherwise return
tonumber(value).
]]--
function parse_numeric_input(value, name)
	val = tonumber(value)
	if val == nil then
		print(string.format("Input %s must be a number.", name))
		require ("os")
		os.exit()
	end
	return val
end

--[[
Perform a deep copy of a table.
]]--
function copytable(orig)
    local orig_type = type(orig)
    local copy
    if orig_type == 'table' then
        copy = {}
        for orig_key, orig_value in next, orig, nil do
            copy[copytable(orig_key)] = copytable(orig_value)
        end
        setmetatable(copy, copytable(getmetatable(orig)))
    else -- number, string, boolean, etc
        copy = orig
    end
    return copy
end

--[[
Add the content of a table at the end of another one.
]]--
function concattable(dst, src)
    for i=1,#src do
        dst[#dst + 1] = src[i]
    end
    
    return dst
end

--[[
return the type of a variable.
]]--
function typeof(var)
    local _type = type(var);
    if(_type ~= "table" and _type ~= "userdata") then
        return _type;
    end
    local _meta = getmetatable(var);
    if(_meta ~= nil and _meta._NAME ~= nil) then
        return _meta._NAME;
    else
        return _type;
    end
end
