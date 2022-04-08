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

application::run_result application::init_inspector()
{
	run_result ret;

	m_state->inspector->set_buffer_format(m_options.event_buffer_format);

	// If required, set the CRI paths
	for (auto &p : m_options.cri_socket_paths)
	{
		if (!p.empty())
		{
			m_state->inspector->add_cri_socket_path(p);
		}
	}

	// Decide whether to do sync or async for CRI metadata fetch
	m_state->inspector->set_cri_async(!m_options.disable_cri_async);

	//
	// If required, set the snaplen
	//
	if(m_options.snaplen != 0)
	{
		m_state->inspector->set_snaplen(m_options.snaplen);
	}

	if(!m_options.all_events)
	{
		// Drop EF_DROP_SIMPLE_CONS kernel side
		m_state->inspector->set_simple_consumer();
		// Eventually, drop any EF_DROP_SIMPLE_CONS event
		// that reached userspace (there are some events that are not syscall-based
		// like signaldeliver, that have the EF_DROP_SIMPLE_CONS flag)
		m_state->inspector->set_drop_event_flags(EF_DROP_SIMPLE_CONS);
	}

	m_state->inspector->set_hostname_and_port_resolution_mode(false);

#ifndef MINIMAL_BUILD

		falco_logger::log(LOG_DEBUG, "Setting metadata download max size to " + to_string(m_state->config->m_metadata_download_max_mb) + " MB\n");
		falco_logger::log(LOG_DEBUG, "Setting metadata download chunk wait time to " + to_string(m_state->config->m_metadata_download_chunk_wait_us) + " μs\n");
		falco_logger::log(LOG_DEBUG, "Setting metadata download watch frequency to " + to_string(m_state->config->m_metadata_download_watch_freq_sec) + " seconds\n");
		m_state->inspector->set_metadata_download_params(m_state->config->m_metadata_download_max_mb * 1024 * 1024, m_state->config->m_metadata_download_chunk_wait_us, m_state->config->m_metadata_download_watch_freq_sec);

#endif

#ifndef MINIMAL_BUILD
	//
	// Run k8s, if required
	//
	char *k8s_api_env = NULL;
	if(!m_options.k8s_api.empty() ||
	   (k8s_api_env = getenv("FALCO_K8S_API")))
	{
		// Create string pointers for some config vars
		// and pass to inspector. The inspector then
		// owns the pointers.
		std::string *k8s_api_ptr = new string((!m_options.k8s_api.empty() ? m_options.k8s_api : k8s_api_env));
		std::string *k8s_api_cert_ptr = new string(m_options.k8s_api_cert);
		std::string *k8s_node_name_ptr = new string(m_options.k8s_node_name);

		if(k8s_api_cert_ptr->empty())
		{
			if(char* k8s_cert_env = getenv("FALCO_K8S_API_CERT"))
			{
				*k8s_api_cert_ptr = k8s_cert_env;
			}
		}
		m_state->inspector->init_k8s_client(k8s_api_ptr, k8s_api_cert_ptr, k8s_node_name_ptr, m_options.verbose);
	}

	//
	// Run mesos, if required
	//
	if(!m_options.mesos_api.empty())
	{
		// Differs from init_k8s_client in that it
		// passes a pointer but the inspector does
		// *not* own it and does not use it after
		// init_mesos_client() returns.
		m_state->inspector->init_mesos_client(&(m_options.mesos_api), m_options.verbose);
	}
	else if(char* mesos_api_env = getenv("FALCO_MESOS_API"))
	{
		std::string mesos_api_copy = mesos_api_env;
		m_state->inspector->init_mesos_client(&mesos_api_copy, m_options.verbose);
	}

#endif
	return ret;
}
