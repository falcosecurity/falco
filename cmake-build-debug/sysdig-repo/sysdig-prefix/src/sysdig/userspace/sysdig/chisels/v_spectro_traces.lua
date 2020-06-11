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
	id = "spectro_traces",
	name = "Traces Spectrogram",
	description = "Traces duration spectrogram.",
	tips = {
		"This view offers a spectrogram-based representation of root trace spans durations.",
		"When appled to a selection in a view like 'Trace Summary' or 'Trace List', this view will only show the latency of the selected spans, while their parent and child spans won't be shown. When applied to the whole machine, this view will show the latency of the traces, i.e. the root spans that have just one tag.",
		"If you are in a trace view like 'Traces Summary' or 'Traces List', you can quickly show this spectrogram for a selection by clicking on F12.",
	},
	view_type = "spectrogram",
	applies_to = {"", "span.tag", "span.id", "container.id", "proc.pid", "thread.nametid", "thread.tid", "proc.name", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name", "fd.name", "fd.containername", "fd.directory", "fd.containerdirectory", "fd.containerdirectory"},
	filter = "span.ntags=%depth+1",
	use_defaults = false,
	drilldown_target = "spans_list",
	propagate_filter = false,
	columns = 
	{
		{
			name = "NA",
			field = "span.duration.quantized",
			is_key = true
		},
		{
			name = "LATENCY",
			description = "span latency. This determines the horizontal position of a dot in the chart.",
			field = "span.duration.quantized",
		},
		{
			name = "COUNT",
			description = "number of times a span falls in a certain latency bucket. This determines the color of a dot in the chart.",
			field = "evt.count",
			aggregation = "SUM",
		}
	}
}
