/*
Copyright (C) 2023 The Falco Authors.

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

#include "actions.h"

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::init_clients(falco::app::state& s)
{
#ifndef MINIMAL_BUILD
	// k8s is useful only if the syscall source is enabled
	if (s.enabled_sources.find(falco_common::syscall_source) == s.enabled_sources.end())
	{
		return run_result::ok();
	}

	auto inspector = s.source_infos.at(falco_common::syscall_source)->inspector;

	falco_logger::log(LOG_DEBUG, "Setting metadata download max size to " + std::to_string(s.config->m_metadata_download_max_mb) + " MB\n");
	falco_logger::log(LOG_DEBUG, "Setting metadata download chunk wait time to " + std::to_string(s.config->m_metadata_download_chunk_wait_us) + " μs\n");
	falco_logger::log(LOG_DEBUG, "Setting metadata download watch frequency to " + std::to_string(s.config->m_metadata_download_watch_freq_sec) + " seconds\n");
	inspector->set_metadata_download_params(s.config->m_metadata_download_max_mb * 1024 * 1024, s.config->m_metadata_download_chunk_wait_us, s.config->m_metadata_download_watch_freq_sec);

	//
	// Run k8s, if required
	//
	char *k8s_api_env = NULL;
	if(!s.options.k8s_api.empty() ||
	   (k8s_api_env = getenv("FALCO_K8S_API")))
	{
		// Create string pointers for some config vars
		// and pass to inspector. The inspector then
		// owns the pointers.
		std::string *k8s_api_ptr = new std::string((!s.options.k8s_api.empty() ? s.options.k8s_api : k8s_api_env));
		std::string *k8s_api_cert_ptr = new std::string(s.options.k8s_api_cert);
		std::string *k8s_node_name_ptr = new std::string(s.options.k8s_node_name);

		if(k8s_api_cert_ptr->empty())
		{
			if(char* k8s_cert_env = getenv("FALCO_K8S_API_CERT"))
			{
				*k8s_api_cert_ptr = k8s_cert_env;
			}
		}
		inspector->init_k8s_client(k8s_api_ptr, k8s_api_cert_ptr, k8s_node_name_ptr, s.options.verbose);
	}

	//
	// DEPRECATED!
	// Run mesos, if required
	// todo(leogr): remove in Falco 0,.35
	//
	if(!s.options.mesos_api.empty())
	{
		// Differs from init_k8s_client in that it
		// passes a pointer but the inspector does
		// *not* own it and does not use it after
		// init_mesos_client() returns.
		falco_logger::log(LOG_WARNING, "Mesos support has been DEPRECATED and will be removed in the next version!\n");
		inspector->init_mesos_client(&(s.options.mesos_api), s.options.verbose);
	}
	else if(char* mesos_api_env = getenv("FALCO_MESOS_API"))
	{
		falco_logger::log(LOG_WARNING, "Mesos support has been DEPRECATED and will be removed in the next version!\n");
		std::string mesos_api_copy = mesos_api_env;
		inspector->init_mesos_client(&mesos_api_copy, s.options.verbose);
	}
#endif

	return run_result::ok();
}
