/*
Copyright (C) 2016-2018 Draios Inc dba Sysdig.

This file is part of falco.

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

#include "event_drops.h"
#include "falco_outputs.h"

class yaml_configuration
{
public:
	std::string m_path;
	yaml_configuration(const std::string& path)
	{
		m_path = path;
		YAML::Node config;
		std::vector<falco_outputs::output_config> outputs;
		try
		{
			m_root = YAML::LoadFile(path);
		}
		catch (const YAML::BadFile& ex)
		{
			std::cerr << "Error reading config file (" + path + "): " + ex.what() + "\n";
			throw;
		}
		catch (const YAML::ParserException& ex)
		{
			std::cerr << "Cannot read config file (" + path + "): " + ex.what() + "\n";
			throw;
		}
	}

	/**
	* Get a scalar value defined at the top level of the config
	*/
	template<typename T>
	const T get_scalar(const std::string& key, const T& default_value)
	{
		try
		{
			auto node = m_root[key];
			if (node.IsDefined())
			{
				return node.as<T>();
			}
		} catch (const YAML::BadConversion& ex)
		{
			std::cerr << "Cannot read config file (" + m_path + "): wrong type at key " + key + "\n";
			throw;
		}

		return default_value;
	}

	/**
	 * Set the top-level node identified by key to value
	 */
	template<typename T>
	void set_scalar(const std::string &key, const T& value)
	{
		auto node = m_root;
		if (node.IsDefined())
		{
			node[key] = value;
		}
	}

	/**
	* Get a scalar value defined inside a 2 level nested structure like:
	* file_output:
	*   enabled: true
	*   filename: output_file.txt
	*
	* get_scalar<bool>("file_output", "enabled", false)
	*/
	template<typename T>
	const T get_scalar(const std::string& key, const std::string& subkey, const T& default_value)
	{
		try
		{
			auto node = m_root[key][subkey];
			if (node.IsDefined())
			{
				return node.as<T>();
			}
		}
		catch (const YAML::BadConversion& ex)
		{
			std::cerr << "Cannot read config file (" + m_path + "): wrong type at key " + key + "\n";
			throw;
		}

		return default_value;
	}

	/**
	 * Set the second-level node identified by key[key][subkey] to value.
	 */
	template<typename T>
	void set_scalar(const std::string& key, const std::string& subkey, const T& value)
	{
		auto node = m_root;
		if (node.IsDefined())
		{
			node[key][subkey] = value;
		}
	}

	// called with the last variadic arg (where the sequence is expected to be found)
	template <typename T>
	void get_sequence_from_node(T& ret, const YAML::Node &node)
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

	// called with the last variadic arg (where the sequence is expected to be found)
	template <typename T>
	void get_sequence(T& ret, const std::string& name)
	{
		return get_sequence_from_node<T>(ret, m_root[name]);
	}

	// called with the last variadic arg (where the sequence is expected to be found)
	template <typename T>
		void get_sequence(T& ret, const std::string& key, const std::string &subkey)
	{
		try
		{
			auto node = m_root[key];
			if (node.IsDefined())
			{
				return get_sequence_from_node<T>(ret, node[subkey]);
			}
		}
		catch (const YAML::BadConversion& ex)
		{
			std::cerr << "Cannot read config file (" + m_path + "): wrong type at key " + key + "\n";
			throw;
		}
	}

private:
	YAML::Node m_root;
};


class falco_configuration
{
 public:
	falco_configuration();
	virtual ~falco_configuration();

	void init(std::string conf_filename, std::list<std::string> &cmdline_options);
	void init(std::list<std::string> &cmdline_options);

	static void read_rules_file_directory(const string &path, list<string> &rules_filenames);

	std::list<std::string> m_rules_filenames;
	bool m_json_output;
	bool m_json_include_output_property;
	std::vector<falco_outputs::output_config> m_outputs;
	uint32_t m_notifications_rate;
	uint32_t m_notifications_max_burst;

	falco_common::priority_type m_min_priority;

	bool m_buffered_outputs;
	bool m_time_format_iso_8601;

	bool m_webserver_enabled;
	uint32_t m_webserver_listen_port;
	std::string m_webserver_k8s_audit_endpoint;
	bool m_webserver_ssl_enabled;
	std::string m_webserver_ssl_certificate;
	std::set<syscall_evt_drop_mgr::action> m_syscall_evt_drop_actions;
	double m_syscall_evt_drop_rate;
	double m_syscall_evt_drop_max_burst;

	// Only used for testing
	bool m_syscall_evt_simulate_drops;


 private:
	void init_cmdline_options(std::list<std::string> &cmdline_options);

	/**
	 * Given a <key>=<value> specifier, set the appropriate option
	 * in the underlying yaml config. <key> can contain '.'
	 * characters for nesting. Currently only 1- or 2- level keys
	 * are supported and only scalar values are supported.
	 */
	void set_cmdline_option(const std::string &spec);

	yaml_configuration* m_config;
};

