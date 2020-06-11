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
description = "Show a log of all HTTP requests";
short_description = "HTTP requests log";
category = "Application";
args = {}

require "http"

-- Initialization callback
function on_init()
    http_init()
    -- The -pc or -pcontainer options was supplied on the cmd line
    print_container = sysdig.is_print_container_data()

    return true
end

function on_transaction(transaction)
    if print_container then
        container = " " .. transaction["container"] .. " "
    else
        container = " "
    end
    print(string.format("%s%s%s method=%s url=%s response_code=%d latency=%dms size=%dB",
                evt.field(datetime_field),
                container,
                transaction["dir"],
                transaction["request"]["method"],
                transaction["request"]["url"],
                transaction["response"]["code"],
                (transaction["response"]["ts"] - transaction["request"]["ts"])/1000000,
                transaction["response"]["length"]
            ))
end

function on_event()
    run_http_parser(evt, on_transaction)
end
