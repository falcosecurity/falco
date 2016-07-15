#pragma once

#include <yaml-cpp/yaml.h>
#include <string>
#include <vector>
#include <list>
#include <iostream>

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

	std::string m_rules_filename;
	bool m_json_output;
	std::vector<falco_outputs::output_config> m_outputs;
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

