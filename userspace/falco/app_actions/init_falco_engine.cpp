/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "application.h"
#include <plugin_manager.h>

using namespace falco::app;

void application::configure_output_format()
{
	std::string output_format;
	bool replace_container_info = false;

	if(m_options.print_additional == "c" || m_options.print_additional == "container")
	{
		output_format = "container=%container.name (id=%container.id)";
		replace_container_info = true;
	}
	else if(m_options.print_additional == "container-gvisor")
	{
		output_format = "container=%container.name (id=%container.id) vpid=%proc.vpid vtid=%thread.vtid";
		replace_container_info = true;
	}
	else if(m_options.print_additional == "k" || m_options.print_additional == "kubernetes")
	{
		output_format = "k8s.ns=%k8s.ns.name k8s.pod=%k8s.pod.name container=%container.id";
		replace_container_info = true;
	}
	else if(m_options.print_additional == "kubernetes-gvisor")
	{
		output_format = "k8s.ns=%k8s.ns.name k8s.pod=%k8s.pod.name container=%container.id vpid=%proc.vpid vtid=%thread.vtid";
		replace_container_info = true;
	}
	else if(m_options.print_additional == "m" || m_options.print_additional == "mesos")
	{
		output_format = "task=%mesos.task.name container=%container.id";
		replace_container_info = true;
	}
	else if(!m_options.print_additional.empty())
	{
		output_format = m_options.print_additional;
		replace_container_info = false;
	}

	if(!output_format.empty())
	{
		m_state->engine->set_extra(output_format, replace_container_info);
	}
}

void application::add_source_to_engine(const std::string& src)
{
	auto src_info = m_state->source_infos.at(src);
	std::shared_ptr<gen_event_filter_factory> filter_factory = nullptr;
	std::shared_ptr<gen_event_formatter_factory> formatter_factory = nullptr;

	if (src == falco_common::syscall_source)
	{
		filter_factory = std::shared_ptr<gen_event_filter_factory>(
			new sinsp_filter_factory(src_info->inspector.get()));
		formatter_factory = std::shared_ptr<gen_event_formatter_factory>(
			new sinsp_evt_formatter_factory(src_info->inspector.get()));
	}
	else
	{
		auto &filterchecks = m_state->source_infos.at(src)->filterchecks;
		filter_factory = std::shared_ptr<gen_event_filter_factory>(
			new sinsp_filter_factory(src_info->inspector.get(), filterchecks));
		formatter_factory = std::shared_ptr<gen_event_formatter_factory>(
			new sinsp_evt_formatter_factory(src_info->inspector.get(), filterchecks));
	}

	if(m_state->config->m_json_output)
	{
		formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
	}

	src_info->engine_idx = m_state->engine->add_source(
		src, filter_factory, formatter_factory);
}

application::run_result application::init_falco_engine()
{
	// add all non-syscall event sources in engine
	for (const auto& src : m_state->loaded_sources)
	{
		if (src != falco_common::syscall_source)
		{
			// we skip the syscall as we want it to be the one added for last
			// in the engine. This makes the source index assignment easier.
			add_source_to_engine(src);
		}
	}

	// add syscall as last source
	add_source_to_engine(falco_common::syscall_source);

	// note: in capture mode, we can assume that the plugin source index will
	// be the same in both the falco engine and the sinsp plugin manager.
	// This assumption stands because the plugin manager stores sources in a
	// vector, and the syscall source is appended in the engine *after* the sources
	// coming from plugins. The reason why this can't work with live mode,
	// is because in that case event sources are scattered across different
	// inspectors. Since this is an implementation-based assumption, we
	// check this and return an error to spot regressions in the future.
	if (is_capture_mode())
	{
		auto manager = m_state->offline_inspector->get_plugin_manager();
		for (const auto &p : manager->plugins())
		{
			if (p->caps() & CAP_SOURCING)
			{
				bool added = false;
				auto source_idx = manager->source_idx_by_plugin_id(p->id(), added);
				auto engine_idx = m_state->source_infos.at(p->event_source())->engine_idx;
				if (!added || source_idx != engine_idx)
				{
					return run_result::fatal("Could not add event source in the engine: " + p->event_source());
				}
			}
		}
	}

	configure_output_format();
	m_state->engine->set_min_priority(m_state->config->m_min_priority);

	return run_result::ok();
}
