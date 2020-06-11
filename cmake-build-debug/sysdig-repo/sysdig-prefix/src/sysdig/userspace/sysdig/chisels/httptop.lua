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
description = "Show top HTTP requests by: ncalls, time or bytes";
short_description = "Top HTTP requests";
category = "Application";

-- Chisel argument list
args = {
    {
        name = "by",
        description = "Show top HTTP transactions by: ncalls, time or bytes, default is ncalls",
        argtype = "string",
        optional = true
    },
}

require "common"
terminal = require "ansiterminal"
require "http"

vizinfo =
{
    key_fld = {"method", "url"},
    key_desc = {"method", "url"},
    value_fld = "ncalls",
    value_desc = "ncalls",
    value_units = "none",
    top_number = 30,
    output_format = "normal"
}

by_field = "ncalls"

-- Argument notification callback
function on_set_arg(name, val)
    if name == "by" then
        if val == "time" then
            vizinfo["value_fld"] = "time"
            vizinfo["value_desc"] = "time"
            vizinfo["value_units"] = "time"
        elseif val == "ncalls" then
            vizinfo["value_fld"] = "ncalls"
            vizinfo["value_desc"] = "ncalls"
            vizinfo["value_units"] = "none"
        elseif val == "bytes" then
            vizinfo["value_fld"] = "bytes"
            vizinfo["value_desc"] = "bytes"
            vizinfo["value_units"] = "bytes"
        else
            print("Invalid argument! Valid options: ncalls, bytes, time")
            return false
        end
        by_field = val
        return true
    end
end


-- Initialization callback
function on_init()
    http_init()
    -- The -pc or -pcontainer options was supplied on the cmd line
    print_container = sysdig.is_print_container_data()

    if print_container then
        table.insert(vizinfo["key_fld"], 1, "container")
        table.insert(vizinfo["key_desc"], 1, "container")
    end

    return true
end

islive = false
grtable = {}
partial_transactions = {}

function build_grtable_key(transaction)
    request = transaction["request"]
    ret = ""
    if print_container then
        ret = transaction["container"] .. "\001\001"
    end
    ret = ret .. string.format("%s\001\001%s", request["method"], request["url"])
    return ret
end

function on_transaction(transaction)
    grtable_key = build_grtable_key(transaction)
    if not grtable[grtable_key] then
        grtable[grtable_key] = {}
    end
    table.insert(grtable[grtable_key], transaction)
end

function on_event()
    run_http_parser(evt, on_transaction)
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

function aggregate_grtable()
    for key, transactions in pairs(grtable) do
        if by_field == "ncalls" then
            grtable[key] = #transactions
        elseif by_field == "bytes" then
            total_bytes = 0
            for _, tr in ipairs(transactions) do
                total_bytes = total_bytes + tr["response"]["length"]
            end
            grtable[key] = total_bytes
        elseif by_field == "time" then
            total_time = 0
            for _, tr in ipairs(transactions) do
                total_time = total_time + tr["response"]["ts"] - tr["request"]["ts"]
            end
            grtable[key] = total_time / #transactions
        end
    end
end

function on_interval(ts_s, ts_ns, delta)
    if vizinfo.output_format ~= "json" then
        terminal.clearscreen()
        terminal.moveto(0, 0)
    end

    aggregate_grtable()
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

    aggregate_grtable()
    print_sorted_table(grtable, ts_s, 0, delta, vizinfo)

    return true
end
