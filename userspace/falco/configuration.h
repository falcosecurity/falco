/*
Copyright (C) 2021 The Falco Authors.

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

#include "event_drops.h"
#include "falco_outputs.h"

class yaml_configuration
{
public:
	/**
	* Load the YAML document represented by the input string.
	*/
	void load_from_string(const std::string& input)
	{
		m_root = YAML::Load(input);
	}

	/**
	* Load the YAML document from the given file path.
	*/
	void load_from_file(const std::string& path)
	{
		m_root = YAML::LoadFile(path);
	}

	/**
	 * Clears the internal loaded document.
	 */
	void clear()
	{
		m_root = YAML::Node();
	}

	/**
	* Get a scalar value from the node identified by key.
	*/
	template<typename T>
	const T get_scalar(const std::string& key, const T& default_value)
	{
		YAML::Node node;
		get_node(node, key);
		if(node.IsDefined())
		{
			return node.as<T>();
		}

		return default_value;
	}

	/**
	 * Set the node identified by key to value.
	 */
	template<typename T>
	void set_scalar(const std::string& key, const T& value)
	{
		YAML::Node node;
		get_node(node, key);
		node = value;
	}

	/**
	* Get the sequence value from the node identified by key.
	*/
	template<typename T>
	void get_sequence(T& ret, const std::string& key)
	{
		YAML::Node node;
		get_node(node, key);
		return get_sequence_from_node<T>(ret, node);
	}

	/**
	* Return true if the node identified by key is defined.
	*/
	bool is_defined(const std::string& key)
	{
		YAML::Node node;
		get_node(node, key);
		return node.IsDefined();
	}

private:
	YAML::Node m_root;
	std::string m_input;
	bool m_is_from_file;

	/**
	 * Key is a string representing a node in the YAML document.
	 * The provided key string can navigate the document in its
	 * nested nodes, with arbitrary depth. The key string follows
	 * this regular language:
	 * 
	 * Key 		:= NodeKey ('.' NodeKey)*
	 * NodeKey	:= (any)+ ('[' (integer)+ ']')*
	 * 
	 * Some examples of accepted key strings:
	 * - NodeName
	 * - ListValue[3].subvalue
	 * - MatrixValue[1][3]
	 * - value1.subvalue2.subvalue3
	 */
	void get_node(YAML::Node &ret, const std::string &key)
	{
		try
		{
			char c;
			bool should_shift;
			std::string nodeKey;
			ret.reset(m_root);
			for(std::string::size_type i = 0; i < key.size(); ++i)
			{
				c = key[i];
				should_shift = c == '.' || c == '[' || i == key.size() - 1;

				if (c != '.' && c != '[')
				{
					if (i > 0 && nodeKey.empty() && key[i - 1] != '.')
					{
						throw runtime_error(
							"Parsing error: expected '.' character at pos " 
							+ to_string(i - 1));
					}
					nodeKey += c;
				}

				if (should_shift)
				{
					if (nodeKey.empty())
					{
						throw runtime_error(
							"Parsing error: unexpected character at pos " 
							+ to_string(i));
					}
					ret.reset(ret[nodeKey]);
					nodeKey.clear();
				}
				if (c == '[')
				{
					auto close_param_idx = key.find(']', i);
					int nodeIdx = std::stoi(key.substr(i + 1, close_param_idx - i - 1));
					ret.reset(ret[nodeIdx]);
					i = close_param_idx;
					if (i < key.size() - 1 && key[i + 1] == '.')
					{
						i++;
					}
				}
			}
		}
		catch(const std::exception& e)
		{
			throw runtime_error("Config error at key \"" + key + "\": " + string(e.what()));
		}
	}
	
	template<typename T>
	void get_sequence_from_node(T& ret, const YAML::Node& node)
	{
		if(node.IsDefined())
		{
			if(node.IsSequence())
			{
				for(const YAML::Node& item : node)
				{
					ret.insert(ret.end(), item.as<typename T::value_type>());
				}
			}
			else if(node.IsScalar())
			{
				ret.insert(ret.end(), node.as<typename T::value_type>());
			}
		}
	}
};

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
	virtual ~falco_configuration();

	void init(std::string conf_filename, const std::vector<std::string>& cmdline_options);
	void init(const std::vector<std::string>& cmdline_options);

	static void read_rules_file_directory(const string& path, list<string>& rules_filenames);

	std::list<std::string> m_rules_filenames;
	bool m_json_output;
	bool m_json_include_output_property;
	bool m_json_include_tags_property;
	std::string m_log_level;
	std::vector<falco::outputs::config> m_outputs;
	uint32_t m_notifications_rate;
	uint32_t m_notifications_max_burst;

	falco_common::priority_type m_min_priority;

	bool m_buffered_outputs;
	bool m_time_format_iso_8601;
	uint32_t m_output_timeout;

	bool m_grpc_enabled;
	uint32_t m_grpc_threadiness;
	std::string m_grpc_bind_address;
	std::string m_grpc_private_key;
	std::string m_grpc_cert_chain;
	std::string m_grpc_root_certs;

	bool m_webserver_enabled;
	uint32_t m_webserver_listen_port;
	std::string m_webserver_k8s_audit_endpoint;
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

	std::vector<plugin_config> m_plugins;

private:
	void init_cmdline_options(const std::vector<std::string>& cmdline_options);

	/**
	 * Given a <key>=<value> specifier, set the appropriate option
	 * in the underlying yaml config. <key> can contain '.'
	 * characters for nesting. Currently only 1- or 2- level keys
	 * are supported and only scalar values are supported.
	 */
	void set_cmdline_option(const std::string& spec);

	yaml_configuration* m_config;
};

namespace YAML {
	template<>
	struct convert<nlohmann::json> {
		static bool decode(const Node& node, nlohmann::json& res)
		{
			int int_val;
			double double_val;
			bool bool_val;
			std::string str_val;
			nlohmann::json sub{};

			switch (node.Type()) {
				case YAML::NodeType::Map:
					for (auto &&it: node)
					{
						YAML::convert<nlohmann::json>::decode(it.second, sub);
						res[it.first.as<std::string>()] = sub;
					}
					break;
				case YAML::NodeType::Sequence:
					for (auto &&it : node)
					{
						YAML::convert<nlohmann::json>::decode(it, sub);
						res.emplace_back(sub);
					}
					break;
				case YAML::NodeType::Scalar:
					if (YAML::convert<int>::decode(node, int_val))
					{
						res = int_val;
					}
					else if (YAML::convert<double>::decode(node, double_val))
					{
						res = double_val;
					}
					else if (YAML::convert<bool>::decode(node, bool_val))
					{
						res = bool_val;
					}
					else if (YAML::convert<std::string>::decode(node, str_val))
					{
						res = str_val;
					}
				default:
					break;
			}
			
			return true;
		}
	};

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
			if(rhs.m_library_path.at(0) != '/')
			{
				// prepend share dir if path is not absolute
				rhs.m_library_path = string(FALCO_ENGINE_PLUGINS_DIR) + rhs.m_library_path;
			}

			if(!node["init_config"])
			{
				return false;
			}
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

			if(node["open_params"])
			{
				rhs.m_open_params = node["open_params"].as<std::string>();
			}

			return true;
		}
	};
}
