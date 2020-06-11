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
	id = "spans_summary",
	name = "Spans Summary",
	description = "Show a summary of a tracer selection's child spans. For each span type, the view reports information like how many times it's been called and how long it took to complete.",
	tips = {
		"Only the spans spans that are direct childs of the selection (i.e. the spans with one more tag than the selection) are shown. Drilling down allows you to explore the further levels.",
		"This view collapses multiple spans with the same tag into a single entry. If you instead want to see each span as a separate entry, use the 'Spans List' view.",
	},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"span.tag", "span.id", "span.time", "span.parenttime", "container.id", "proc.pid", "thread.nametid", "proc.name", "thread.tid", "fd.directory", "fd.containerdirectory", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	use_defaults = true,
	filter = "span.ntags>=%depth+1",
	drilldown_target = "spans_summary",
	spectro_type = "tracers",
	drilldown_increase_depth = true,
	columns = 
	{
		{
			name = "NA",
			field = "span.tag[%depth]",
			is_key = true
		},
		{
			is_sorting = true,
			name = "HITS",
			field = "span.count.fortag[%depth]",
			description = "number of times the span with the given tag has been hit.",
			colsize = 10,
			aggregation = "SUM"
		},
		{
			name = "AVG TIME",
			field = "span.duration.fortag[%depth]",
			description = "the average time this span took to complete.",
			colsize = 10,
			aggregation = "AVG"
		},
		{
			name = "MIN TIME",
			field = "span.duration.fortag[%depth]",
			description = "the minimum time this span took to complete.",
			colsize = 10,
			aggregation = "MIN"
		},
		{
			name = "MAX TIME",
			field = "span.duration.fortag[%depth]",
			description = "the maximum time this span took to complete.",
			colsize = 10,
			aggregation = "MAX"
		},
		{
			name = "CHD HITS",
			field = "span.childcount.fortag[%depth]",
			description = "number of times any child of the span with the given tag has been hit. This is useful to determine if the span is a leaf or if it has childs nested in it.",
			colsize = 10,
			aggregation = "SUM"
		},
		{
			name = "TAG",
			field = "span.tag[%depth]",
			description = "span tag.",
			colsize = 256,
			aggregation = "SUM"
		},
	}
}
