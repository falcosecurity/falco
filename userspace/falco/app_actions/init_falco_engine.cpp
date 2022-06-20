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
	else if(m_options.print_additional == "k" || m_options.print_additional == "kubernetes")
	{
		output_format = "k8s.ns=%k8s.ns.name k8s.pod=%k8s.pod.name container=%container.id";
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
	else if(m_options.gvisor_config != "")
	{
		output_format = "container=%container.id pid=%proc.vpid tid=%thread.vtid ";
		replace_container_info = true;
	}

	if(!output_format.empty())
	{
		m_state->engine->set_extra(output_format, replace_container_info);
	}
}

application::run_result application::init_falco_engine()
{
	configure_output_format();

	// Create "factories" that can create filters/formatters for syscalls

	// libs requires raw pointer, we should modify libs to use reference/shared_ptr
	std::shared_ptr<gen_event_filter_factory> syscall_filter_factory(new sinsp_filter_factory(m_state->inspector.get()));

	// libs requires raw pointer, we should modify libs to use reference/shared_ptr
	std::shared_ptr<gen_event_formatter_factory> syscall_formatter_factory(new sinsp_evt_formatter_factory(m_state->inspector.get()));

	m_state->syscall_source_idx = m_state->engine->add_source(falco_common::syscall_source, syscall_filter_factory, syscall_formatter_factory);
	
	if(m_state->config->m_json_output)
	{
		syscall_formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
	}

	for(const auto &src : m_options.disable_sources)
	{
		if (m_state->enabled_sources.find(src) == m_state->enabled_sources.end())
		{
			return run_result::fatal("Attempted disabling unknown event source: " + src);
		}
		m_state->enabled_sources.erase(src);
	}

	// todo(jasondellaluce,leogr): change this once we attain multiple active source
	if(m_state->enabled_sources.empty())
	{
		return run_result::fatal("At least one event source needs to be enabled");
	}

	m_state->engine->set_min_priority(m_state->config->m_min_priority);

	return run_result::ok();
}
