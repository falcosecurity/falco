// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

// Falco only metric
#define METRICS_V2_JEMALLOC_STATS 1 << 31

enum class engine_kind_t : uint8_t { KMOD, MODERN_EBPF, REPLAY, NODRIVER };

enum class capture_mode_t : uint8_t { RULES, ALL_RULES };

// Map that holds { config filename | validation status } for each loaded config file.
typedef std::map<std::string, std::string> config_loaded_res;

class falco_configuration {
public:
	struct plugin_config {
		std::string m_name;
		std::string m_library_path;
		std::string m_init_config;
		std::string m_open_params;
	};

	struct config_files_config {
		std::string m_path;
		yaml_helper::config_files_strategy m_strategy;
	};

	struct kmod_config {
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

	struct webserver_config {
		uint32_t m_threadiness = 0;
		uint32_t m_listen_port = 8765;
		std::string m_listen_address = "0.0.0.0";
		std::string m_k8s_healthz_endpoint = "/healthz";
		bool m_ssl_enabled = false;
		std::string m_ssl_certificate;
		bool m_prometheus_metrics_enabled = false;
	};

	enum class rule_selection_operation { enable, disable };

	struct rule_selection_config {
		rule_selection_operation m_op;
		std::string m_tag;
		std::string m_rule;
	};

	struct append_output_config {
		std::string m_source;
		std::set<std::string> m_tags;
		std::string m_rule;
		std::string m_format;
		bool m_suggested_output = false;
		std::unordered_map<std::string, std::string> m_formatted_fields;
		std::set<std::string> m_raw_fields;
	};

	falco_configuration();
	virtual ~falco_configuration() = default;

	config_loaded_res init_from_file(const std::string& conf_filename,
	                                 const std::vector<std::string>& cmdline_options);
	config_loaded_res init_from_content(const std::string& config_content,
	                                    const std::vector<std::string>& cmdline_options,
	                                    const std::string& filename = "default");

	std::string dump();

	static void read_rules_file_directory(const std::string& path,
	                                      std::list<std::string>& rules_filenames,
	                                      std::list<std::string>& rules_folders);

	// Config list as passed by the user. Filenames.
	std::list<std::string> m_loaded_configs_filenames;
	// Map with filenames and their sha256 of the loaded configs files
	std::unordered_map<std::string, std::string> m_loaded_configs_filenames_sha256sum;
	// Config list as passed by the user. Folders.
	std::list<std::string> m_loaded_configs_folders;

	// Rules list as passed by the user
	std::list<std::string> m_rules_filenames;
	// Actually loaded rules, with folders inspected
	std::list<std::string> m_loaded_rules_filenames;
	// Map with filenames and their sha256 of the loaded rules files
	std::unordered_map<std::string, std::string> m_loaded_rules_filenames_sha256sum;
	// List of loaded rule folders
	std::list<std::string> m_loaded_rules_folders;
	// Rule selection options passed by the user
	std::vector<rule_selection_config> m_rules_selection;
	// Append output configuration passed by the user
	std::vector<append_output_config> m_append_output;
	// Static fields configuration passed by the user
	std::map<std::string, std::string> m_static_fields;

	bool m_json_output;
	bool m_json_include_output_property;
	bool m_json_include_tags_property;
	bool m_json_include_message_property;
	bool m_json_include_output_fields_property;
	std::string m_log_level;
	std::vector<falco::outputs::config> m_outputs;

	falco_common::priority_type m_min_priority;
	falco_common::rule_matching m_rule_matching;

	bool m_watch_config_files;
	bool m_buffered_outputs;
	size_t m_outputs_queue_capacity;
	bool m_time_format_iso_8601;
	bool m_buffer_format_base64;
	uint32_t m_output_timeout;

	bool m_webserver_enabled;
	webserver_config m_webserver_config;

	syscall_evt_drop_actions m_syscall_evt_drop_actions;
	double m_syscall_evt_drop_threshold;
	double m_syscall_evt_drop_rate;
	double m_syscall_evt_drop_max_burst;
	// Only used for testing
	bool m_syscall_evt_simulate_drops;

	uint32_t m_syscall_evt_timeout_max_consecutives;

	uint32_t m_falco_libs_thread_table_size;
	uint32_t m_falco_libs_thread_table_auto_purging_interval_s;
	uint32_t m_falco_libs_thread_table_auto_purging_thread_timeout_s;
	uint64_t m_falco_libs_snaplen;

	// User supplied base_syscalls, overrides any Falco state engine enforcement.
	std::unordered_set<std::string> m_base_syscalls_custom_set;
	bool m_base_syscalls_all;
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
	bool m_plugins_hostinfo;

	// capture configs
	bool m_capture_enabled;
	std::string m_capture_path_prefix;
	capture_mode_t m_capture_mode = capture_mode_t::RULES;
	uint64_t m_capture_default_duration_ns;

	// Falco engine
	engine_kind_t m_engine_mode = engine_kind_t::KMOD;
	kmod_config m_kmod = {};
	modern_ebpf_config m_modern_ebpf = {};
	replay_config m_replay = {};

	yaml_helper m_config;

	//
	// Runtime-Generated values (not user-configurable)
	//

	// JSON schema generated from a hardcoded string
	nlohmann::json m_config_schema;
	// Timestamp of most recent configuration reload
	int64_t m_falco_reload_ts{0};

private:
	void merge_config_files(const std::string& config_name, config_loaded_res& res);
	void load_yaml(const std::string& config_name);
	void init_logger();
	void load_engine_config(const std::string& config_name);
	void init_cmdline_options(const std::vector<std::string>& cmdline_options);
	void load_cmdline_config_files(const std::vector<std::string>& cmdline_options);

	/**
	 * Given a <key>=<value> specifier, set the appropriate option
	 * in the underlying yaml config. <key> can contain '.'
	 * characters for nesting. Currently only 1- or 2- level keys
	 * are supported and only scalar values are supported.
	 */
	void set_cmdline_option(const std::string& spec);
};

namespace YAML {
template<>
struct convert<falco_configuration::append_output_config> {
	static bool decode(const Node& node, falco_configuration::append_output_config& rhs) {
		if(!node.IsMap()) {
			return false;
		}

		if(node["match"]) {
			auto& match = node["match"];

			if(match["source"]) {
				rhs.m_source = match["source"].as<std::string>();
			}

			if(match["tags"] && match["tags"].IsSequence()) {
				for(auto& tag : match["tags"]) {
					if(!tag.IsScalar()) {
						return false;
					}

					rhs.m_tags.insert(tag.as<std::string>());
				}
			}

			if(match["rule"]) {
				rhs.m_rule = match["rule"].as<std::string>();
			}
		}

		if(node["extra_output"]) {
			rhs.m_format = node["extra_output"].as<std::string>();
		}

		if(node["extra_fields"]) {
			if(!node["extra_fields"].IsSequence()) {
				return false;
			}

			for(auto& field_definition : node["extra_fields"]) {
				if(field_definition.IsMap() && field_definition.size() == 1) {
					YAML::const_iterator def = field_definition.begin();
					std::string key = def->first.as<std::string>();

					// it is an error to redefine an existing key
					if(rhs.m_formatted_fields.count(key) != 0 || rhs.m_raw_fields.count(key) != 0) {
						return false;
					}

					rhs.m_formatted_fields[key] = def->second.as<std::string>();
				} else if(field_definition.IsScalar()) {
					std::string key = field_definition.as<std::string>();

					// it is an error to redefine an existing key
					if(rhs.m_formatted_fields.count(key) != 0) {
						return false;
					}

					rhs.m_raw_fields.insert(key);
				} else {
					return false;
				}
			}
		}

		if(node["suggested_output"]) {
			rhs.m_suggested_output = node["suggested_output"].as<bool>();
		}

		return true;
	}
};

template<>
struct convert<falco_configuration::rule_selection_config> {
	static Node encode(const falco_configuration::rule_selection_config& rhs) {
		Node node;
		Node subnode;
		if(rhs.m_rule != "") {
			subnode["rule"] = rhs.m_rule;
		}

		if(rhs.m_tag != "") {
			subnode["tag"] = rhs.m_tag;
		}

		if(rhs.m_op == falco_configuration::rule_selection_operation::enable) {
			node["enable"] = subnode;
		} else if(rhs.m_op == falco_configuration::rule_selection_operation::disable) {
			node["disable"] = subnode;
		}

		return node;
	}

	static bool decode(const Node& node, falco_configuration::rule_selection_config& rhs) {
		if(!node.IsMap()) {
			return false;
		}

		if(node["enable"]) {
			rhs.m_op = falco_configuration::rule_selection_operation::enable;

			const Node& enable = node["enable"];
			if(!enable.IsMap()) {
				return false;
			}

			if(enable["rule"]) {
				rhs.m_rule = enable["rule"].as<std::string>();
			}
			if(enable["tag"]) {
				rhs.m_tag = enable["tag"].as<std::string>();
			}
		} else if(node["disable"]) {
			rhs.m_op = falco_configuration::rule_selection_operation::disable;

			const Node& disable = node["disable"];
			if(!disable.IsMap()) {
				return false;
			}

			if(disable["rule"]) {
				rhs.m_rule = disable["rule"].as<std::string>();
			}
			if(disable["tag"]) {
				rhs.m_tag = disable["tag"].as<std::string>();
			}
		} else {
			return false;
		}

		if(rhs.m_rule == "" && rhs.m_tag == "") {
			return false;
		}

		return true;
	}
};

template<>
struct convert<falco_configuration::plugin_config> {
	// Note that this loses the distinction between init configs
	// defined as YAML maps or as opaque strings.
	static Node encode(const falco_configuration::plugin_config& rhs) {
		Node node;
		node["name"] = rhs.m_name;
		node["library_path"] = rhs.m_library_path;
		node["init_config"] = rhs.m_init_config;
		node["open_params"] = rhs.m_open_params;
		return node;
	}

	static bool decode(const Node& node, falco_configuration::plugin_config& rhs) {
		if(!node.IsMap()) {
			return false;
		}

		if(!node["name"]) {
			return false;
		}
		rhs.m_name = node["name"].as<std::string>();

		if(!node["library_path"]) {
			return false;
		}
		rhs.m_library_path = node["library_path"].as<std::string>();
		if(!rhs.m_library_path.empty() && rhs.m_library_path.at(0) != '/') {
			// prepend share dir if path is not absolute
			rhs.m_library_path = std::string(FALCO_ENGINE_PLUGINS_DIR) + rhs.m_library_path;
		}

		if(node["init_config"] && !node["init_config"].IsNull()) {
			// By convention, if the init config is a YAML map we convert it
			// in a JSON object string. This is useful for plugins implementing
			// the `get_init_schema` API symbol, which right now support the
			// JSON Schema specific. If we ever support other schema/data types,
			// we may want to bundle the conversion logic in an ad-hoc class.
			// The benefit of this is being able of parsing/editing the config as
			// a YAML map instead of having an opaque string.
			if(node["init_config"].IsMap()) {
				nlohmann::json json;
				YAML::convert<nlohmann::json>::decode(node["init_config"], json);
				rhs.m_init_config = json.dump();
			} else {
				rhs.m_init_config = node["init_config"].as<std::string>();
			}
		}

		if(node["open_params"] && !node["open_params"].IsNull()) {
			std::string open_params = node["open_params"].as<std::string>();
			rhs.m_open_params = trim(open_params);
		}

		return true;
	}
};

template<>
struct convert<falco_configuration::config_files_config> {
	static Node encode(const falco_configuration::config_files_config& rhs) {
		Node node;
		node["path"] = rhs.m_path;
		node["strategy"] = yaml_helper::strategy_to_string(rhs.m_strategy);
		return node;
	}

	static bool decode(const Node& node, falco_configuration::config_files_config& rhs) {
		if(!node.IsMap()) {
			// Single string mode defaults to append strategy
			rhs.m_path = node.as<std::string>();
			rhs.m_strategy = yaml_helper::STRATEGY_APPEND;
			return true;
		}

		// Path is required
		if(!node["path"]) {
			return false;
		}
		rhs.m_path = node["path"].as<std::string>();

		// Strategy is not required
		if(!node["strategy"]) {
			rhs.m_strategy = yaml_helper::STRATEGY_APPEND;
		} else {
			std::string strategy = node["strategy"].as<std::string>();
			rhs.m_strategy = yaml_helper::strategy_from_string(strategy);
		}
		return true;
	}
};

}  // namespace YAML
