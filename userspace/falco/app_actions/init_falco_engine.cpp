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

	if(!output_format.empty())
	{
		m_state->engine->set_extra(output_format, replace_container_info);
	}
}

application::run_result application::init_falco_engine()
{
	run_result ret;

	configure_output_format();

	// Create "factories" that can create filters/formatters for
	// syscalls and k8s audit events.

	// libs requires raw pointer, we should modify libs to use reference/shared_ptr
	std::shared_ptr<gen_event_filter_factory> syscall_filter_factory(new sinsp_filter_factory(m_state->inspector.get()));
	std::shared_ptr<gen_event_filter_factory> k8s_audit_filter_factory(new json_event_filter_factory());

	// libs requires raw pointer, we should modify libs to use reference/shared_ptr
	std::shared_ptr<gen_event_formatter_factory> syscall_formatter_factory(new sinsp_evt_formatter_factory(m_state->inspector.get()));
	std::shared_ptr<gen_event_formatter_factory> k8s_audit_formatter_factory(new json_event_formatter_factory(k8s_audit_filter_factory));

	m_state->syscall_source_idx = m_state->engine->add_source(application::s_syscall_source, syscall_filter_factory, syscall_formatter_factory);
	m_state->k8s_audit_source_idx = m_state->engine->add_source(application::s_k8s_audit_source, k8s_audit_filter_factory, k8s_audit_formatter_factory);

	if(m_state->config->m_json_output)
	{
		syscall_formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
		k8s_audit_formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
	}

	for(const auto &src : m_options.disable_sources)
	{
		m_state->enabled_sources.erase(src);
	}

	// XXX/mstemm technically this isn't right, you could disable syscall *and* k8s_audit and configure a plugin.
	if(m_state->enabled_sources.empty())
	{
		throw std::invalid_argument("The event source \"syscall\" and \"k8s_audit\" can not be disabled together");
	}

	m_state->engine->set_min_priority(m_state->config->m_min_priority);

	return ret;
}
