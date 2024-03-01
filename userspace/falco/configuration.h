// SPDX-License-Identifier: Apache-2.0
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

#pragma once

#include <sys/types.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
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

enum class engine_kind_t : uint8_t
{
	KMOD,
	EBPF,
	MODERN_EBPF,
	REPLAY,
	GVISOR,
	NODRIVER
};

class falco_configuration
{
public:
	struct plugin_config {
		std::string m_name;
		std::string m_library_path;
		std::string m_init_config;
		std::string m_open_params;
	};

	struct kmod_config {
		int16_t m_buf_size_preset;
		bool m_drop_failed_exit;
	};

	struct ebpf_config {
		std::string m_probe_path;
		int16_t m_buf_size_preset;
		bool m_drop_failed_exit;
	};

	struct modern_ebpf_config {
		uint16_t m_cpus_for_each_buffer;
		int16_t m_buf_size_preset;
		bool m_drop_failed_exit;
	};

	struct replay_config {
		std::string m_capture_file;
	};

	struct gvisor_config {
		std::string m_config;
		std::string m_root;
	};

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

	falco_common::priority_type m_min_priority;
	falco_common::rule_matching m_rule_matching;

	bool m_watch_config_files;
	bool m_buffered_outputs;
	size_t m_outputs_queue_capacity;
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
	std::string m_webserver_listen_address;
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

	uint32_t m_falco_libs_thread_table_size;

	// User supplied base_syscalls, overrides any Falco state engine enforcement.
	std::unordered_set<std::string> m_base_syscalls_custom_set;
	bool m_base_syscalls_repair;

	// metrics configs
	bool m_metrics_enabled;
	std::string m_metrics_interval_str;
	uint64_t m_metrics_interval;
	bool m_metrics_stats_rule_enabled;
	std::string m_metrics_output_file;
	uint32_t m_metrics_flags;
	bool m_metrics_convert_memory_to_mb;
	bool m_metrics_include_empty_values;
	std::vector<plugin_config> m_plugins;

	// Falco engine
	engine_kind_t m_engine_mode = engine_kind_t::KMOD;
	kmod_config m_kmod = {};
	ebpf_config m_ebpf = {};
	modern_ebpf_config m_modern_ebpf = {};
	replay_config m_replay = {};
	gvisor_config m_gvisor = {};

private:
	void load_yaml(const std::string& config_name, const yaml_helper& config);

	void load_engine_config(const std::string& config_name, const yaml_helper& config);

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
