#pragma once

#include <yaml-cpp/yaml.h>
#include <iostream>

struct output_config
{
	std::string name;
	std::map<std::string, std::string> options;
};

class yaml_configuration
{
public:
	std::string m_path;
	yaml_configuration(const std::string& path)
	{
		m_path = path;
		YAML::Node config;
		std::vector<output_config> outputs;
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

private:
	YAML::Node m_root;
};


class falco_configuration
{
 public:
	void init(std::string conf_filename);
	void init();
	std::string m_rules_filename;
	bool m_json_output;
	std::vector<output_config> m_outputs;
 private:
	yaml_configuration* m_config;
};

