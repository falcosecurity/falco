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

#pragma once

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <yaml-cpp/yaml.h>
#include <string>
#include <vector>
#include <list>
#include <set>
#include <iostream>
#include <fstream>

#include "config_falco.h"
#include "yaml_helper.h"
#include "event_drops.h"
#include "falco_outputs.h"

class falco_configuration
{
public:

	typedef struct {
	public:
		std::string m_name;
		std::string m_library_path;
		std::string m_init_config;
		std::string m_open_params;
	} plugin_config;

	falco_configuration();
	virtual ~falco_configuration() = default;

	void init(const std::string& conf_filename, const std::vector<std::string>& cmdline_options);
	void init(const std::vector<std::string>& cmdline_options);

	static void read_rules_file_directory(const std::string& path, std::list<std::string>& rules_filenames, std::list<std::string> &rules_folders);

	// Rules list as passed by the user
	std::list<std::string> m_rules_filenames;
	// Actually loaded rules, with folders inspected
	std::list<std::string> m_loaded_rules_filenames;
	// List of loaded rule folders
	std::list<std::string> m_loaded_rules_folders;

	bool m_json_output;
	bool m_json_include_output_property;
	bool m_json_include_tags_property;
	std::string m_log_level;
	std::vector<falco::outputs::config> m_outputs;
	uint32_t m_notifications_rate;
	uint32_t m_notifications_max_burst;

	falco_common::priority_type m_min_priority;
	falco_common::rule_matching m_rule_matching;

	bool m_watch_config_files;
	bool m_buffered_outputs;
	size_t m_outputs_queue_capacity;
	falco_common::outputs_queue_recovery_type m_outputs_queue_recovery;
	bool m_time_format_iso_8601;
	uint32_t m_output_timeout;

	bool m_grpc_enabled;
	uint32_t m_grpc_threadiness;
	std::string m_grpc_bind_address;
	std::string m_grpc_private_key;
	std::string m_grpc_cert_chain;
	std::string m_grpc_root_certs;

	bool m_webserver_enabled;
	uint32_t m_webserver_threadiness;
	uint32_t m_webserver_listen_port;
	std::string m_webserver_k8s_healthz_endpoint;
	bool m_webserver_ssl_enabled;
	std::string m_webserver_ssl_certificate;

	syscall_evt_drop_actions m_syscall_evt_drop_actions;
	double m_syscall_evt_drop_threshold;
	double m_syscall_evt_drop_rate;
	double m_syscall_evt_drop_max_burst;
	// Only used for testing
	bool m_syscall_evt_simulate_drops;

	uint32_t m_syscall_evt_timeout_max_consecutives;

	uint32_t m_metadata_download_max_mb;
	uint32_t m_metadata_download_chunk_wait_us;
	uint32_t m_metadata_download_watch_freq_sec;

	// Index corresponding to the syscall buffer dimension.
	uint16_t m_syscall_buf_size_preset;

	// Number of CPUs associated with a single ring buffer.
	uint16_t m_cpus_for_each_syscall_buffer;

	bool m_syscall_drop_failed_exit;

	// User supplied base_syscalls, overrides any Falco state engine enforcement.
	std::unordered_set<std::string> m_base_syscalls_custom_set;
	bool m_base_syscalls_repair;

	// metrics configs
	bool m_metrics_enabled;
	std::string m_metrics_interval_str;
	uint64_t m_metrics_interval;
	bool m_metrics_stats_rule_enabled;
	std::string m_metrics_output_file;
	bool m_metrics_resource_utilization_enabled;
	bool m_metrics_kernel_event_counters_enabled;
	bool m_metrics_libbpf_stats_enabled;
	bool m_metrics_convert_memory_to_mb;
	bool m_metrics_include_empty_values;

	std::vector<plugin_config> m_plugins;

private:
	void load_yaml(const std::string& config_name, const yaml_helper& config);

	void init_cmdline_options(yaml_helper& config, const std::vector<std::string>& cmdline_options);

	/**
	 * Given a <key>=<value> specifier, set the appropriate option
	 * in the underlying yaml config. <key> can contain '.'
	 * characters for nesting. Currently only 1- or 2- level keys
	 * are supported and only scalar values are supported.
	 */
	void set_cmdline_option(yaml_helper& config, const std::string& spec);
};

namespace YAML {
	template<>
	struct convert<falco_configuration::plugin_config> {

		// Note that this loses the distinction between init configs
		// defined as YAML maps or as opaque strings.
		static Node encode(const falco_configuration::plugin_config & rhs) {
			Node node;
			node["name"] = rhs.m_name;
			node["library_path"] = rhs.m_library_path;
			node["init_config"] = rhs.m_init_config;
			node["open_params"] = rhs.m_open_params;
			return node;
		}

		static bool decode(const Node& node, falco_configuration::plugin_config & rhs) {
			if(!node.IsMap())
			{
				return false;
			}

			if(!node["name"])
			{
				return false;
			}
			rhs.m_name = node["name"].as<std::string>();

			if(!node["library_path"])
			{
				return false;
			}
			rhs.m_library_path = node["library_path"].as<std::string>();
			if(!rhs.m_library_path.empty() && rhs.m_library_path.at(0) != '/')
			{
				// prepend share dir if path is not absolute
				rhs.m_library_path = std::string(FALCO_ENGINE_PLUGINS_DIR) + rhs.m_library_path;
			}

			if(node["init_config"] && !node["init_config"].IsNull())
			{
				// By convention, if the init config is a YAML map we convert it
				// in a JSON object string. This is useful for plugins implementing
				// the `get_init_schema` API symbol, which right now support the
				// JSON Schema specific. If we ever support other schema/data types,
				// we may want to bundle the conversion logic in an ad-hoc class.
				// The benefit of this is being able of parsing/editing the config as
				// a YAML map instead of having an opaque string.
				if (node["init_config"].IsMap())
				{
					nlohmann::json json;
					YAML::convert<nlohmann::json>::decode(node["init_config"], json);
					rhs.m_init_config = json.dump();
				}
				else
				{
					rhs.m_init_config = node["init_config"].as<std::string>();
				}
			}

			if(node["open_params"] && !node["open_params"].IsNull())
			{
				std::string open_params = node["open_params"].as<std::string>();
				rhs.m_open_params = trim(open_params);
			}

			return true;
		}
	};
}
