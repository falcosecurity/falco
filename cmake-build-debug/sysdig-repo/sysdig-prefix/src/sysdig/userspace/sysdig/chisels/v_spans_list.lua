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
	id = "spans_list",
	name = "Spans List",
	description = "Show the detailed list of a tracer selection's child spans. For each span type, the view reports information like its arguments and how long it took to complete.",
	tips = {
		"Only the spans spans that are direct childs of the selection (i.e. the spans with one more tag than the selection) are shown. Drilling down allows you to explore the further levels.",
	},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"span.tag", "span.id", "span.time", "span.parenttime", "container.id", "proc.pid", "thread.nametid", "proc.name", "thread.tid", "fd.directory", "fd.containerdirectory", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	use_defaults = true,
	filter = "span.ntags>=%depth+1",
	drilldown_target = "spans_list",
	drilldown_increase_depth = true,
	columns = 
	{
		{
			name = "NA",
			field = "span.rawtime",
			filterfield = "span.rawparenttime",
			is_key = true,
			filter_in_child_only = true,
		},
		{
			name = "ID",
			field = "span.id",
			description = "the unique numeric ID of the span.",
			colsize = 10,
		},
		{
			name = "TIME",
			field = "span.time",
			description = "the time of the span enter tracer.",
			colsize = 19,
		},
		{
			name = "DURATION",
			field = "span.duration.fortag[%depth]",
			description = "the time this span call took to complete",
			colsize = 10,
			aggregation = "AVG",
			is_sorting = true,
		},
		{
			name = "TAG",
			field = "span.tag[%depth]",
			description = "span tag.",
			colsize = 32,
			aggregation = "SUM"
		},
		{
			name = "ARGS",
			field = "span.enterargs",
			description = "span enter arguments.",
			colsize = 256,
			aggregation = "SUM"
		},
	}
}
