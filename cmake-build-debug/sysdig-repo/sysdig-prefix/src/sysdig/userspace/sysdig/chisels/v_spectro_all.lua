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
view_info = 
{
	id = "spectro_all",
	name = "Spectrogram-All",
	description = "System call latency spectrogram.",
	view_type = "spectrogram",
	applies_to = {"evt.type"},
	filter = "evt.dir=<",
	use_defaults = false,
	columns = 
	{
		{
			name = "NA",
			field = "evt.latency.quantized",
			is_key = true
		},
		{
			name = "LATENCY",
			description = "system call latency.",
			field = "evt.latency.quantized",
		},
		{
			name = "COUNT",
			description = "XXX.",
			field = "evt.count",
			aggregation = "SUM",
			colsize = 8,
		}
	}
}
