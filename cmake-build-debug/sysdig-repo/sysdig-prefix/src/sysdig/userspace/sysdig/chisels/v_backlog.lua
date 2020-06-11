--[[

Copyright (C) 2015 Donatas Abraitis.

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

view_info =
{
  id = "backlog",
  name = "Socket Queues",
  description = "This will show queues (backlog) utilization per process. This is useful if you have no clue what's going to with your system with heavy workload on sockets. It would help you to troubleshoot current listen() backlog, maximum backlog, which is configured by application",
  tags = {"Default"},
  view_type = "table",
  applies_to = {"", "proc.pid", "proc.name", "fd.sport", "fd.sproto"},
  filter = "evt.type=accept",
  is_root = false,
  use_defaults = true,
  drilldown_target = "connections",
  columns =
  {
    {
      name = "NA",
      field = "fd.sport",
      is_key = true
    },
    {
      name = "PID",
      field = "proc.pid",
      description = "Process ID",
      colsize = 15
    },
    {
      name = "PORT",
      field = "fd.sport",
      description = "Server port",
      colsize = 15
    },
    {
      name = "BACKLOG",
      field = "evt.arg[3]",
      description = "Current backlog size",
      colsize = 15,
      is_sorting = true,
      aggregation = "AVG"
    },
    {
      name = "BACKLOG_PCT",
      field = "evt.arg[2]",
      description = "Current backlog size in percentage",
      colsize = 15,
      aggregation = "AVG"
    },
    {
      name = "BACKLOG_MAX",
      field = "evt.arg[4]",
      description = "Max backlog size",
      colsize = 15
    },
    {
      name = "PROC",
      field = "proc.name",
      description = "Process name",
      colsize = 50
    },
  }
}
