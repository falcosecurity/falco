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

#include "event_drops.h"
#include "falco_outputs.h"

/**
 * @brief An helper class for reading and editing YAML documents
 */
class yaml_helper
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
	const T get_scalar(const std::string& key, const T& default_value) const
	{
		YAML::Node node;
		get_node(node, key);
		if(node.IsDefined())
		{
			std::string value = node.as<std::string>();

			// Helper function to convert string to the desired type T
			auto convert_str_to_t = [&default_value](const std::string& str) -> T {
				std::stringstream ss(str);
				T result;
				if (ss >> result) return result;
				return default_value;
			};

			// If the value starts with `$$`, check for a subsequent `{...}`
			if (value.size() >= 3 && value[0] == '$' && value[1] == '$')
			{
				// If after stripping the first `$`, the string format is like `${VAR}`, treat it as a plain string and don't resolve.
				if (value[2] == '{' && value[value.size() - 1] == '}')
				{
					value = value.substr(1);
					return convert_str_to_t(value);
				}
				else return convert_str_to_t(value);
			}

			// Check if the value is an environment variable reference
			if(value.size() >= 2 && value[0] == '$' && value[1] == '{' && value[value.size() - 1] == '}')
			{
				// Format: ${ENV_VAR_NAME}
				std::string env_var = value.substr(2, value.size() - 3);

				const char* env_value = std::getenv(env_var.c_str()); // Get the environment variable value
				if(env_value) return convert_str_to_t(env_value);

				return default_value;
			}

			// If it's not an environment variable reference, return the value as is
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
	void get_sequence(T& ret, const std::string& key) const
	{
		YAML::Node node;
		get_node(node, key);
		return get_sequence_from_node<T>(ret, node);
	}

	/**
	* Return true if the node identified by key is defined.
	*/
	bool is_defined(const std::string& key) const
	{
		YAML::Node node;
		get_node(node, key);
		return node.IsDefined();
	}

private:
	YAML::Node m_root;

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
	void get_node(YAML::Node &ret, const std::string &key) const
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
						throw std::runtime_error(
							"Parsing error: expected '.' character at pos "
							+ std::to_string(i - 1));
					}
					nodeKey += c;
				}

				if (should_shift)
				{
					if (nodeKey.empty())
					{
						throw std::runtime_error(
							"Parsing error: unexpected character at pos "
							+ std::to_string(i));
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
			throw std::runtime_error("Config error at key \"" + key + "\": " + std::string(e.what()));
		}
	}

	template<typename T>
	void get_sequence_from_node(T& ret, const YAML::Node& node) const
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

// define a yaml-cpp conversion function for nlohmann json objects
namespace YAML {
	template<>
	struct convert<nlohmann::json> {
		static bool decode(const Node& node, nlohmann::json& res)
		{
			int int_val;
			double double_val;
			bool bool_val;
			std::string str_val;

			switch (node.Type()) {
				case YAML::NodeType::Map:
					for (auto &&it: node)
					{
						nlohmann::json sub{};
						YAML::convert<nlohmann::json>::decode(it.second, sub);
						res[it.first.as<std::string>()] = sub;
					}
					break;
				case YAML::NodeType::Sequence:
					for (auto &&it : node)
					{
						nlohmann::json sub{};
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
}
