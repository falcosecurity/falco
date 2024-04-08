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
#include <filesystem>

#include "config_falco.h"

#include "event_drops.h"
#include "falco_outputs.h"

class yaml_helper;

class yaml_visitor {
private:
	using Callback = std::function<void(YAML::Node&)>;
	explicit yaml_visitor(Callback cb): seen(), cb(std::move(cb)) {}

	void operator()(YAML::Node &cur) {
		seen.push_back(cur);
		if (cur.IsMap()) {
			for (YAML::detail::iterator_value pair : cur) {
				descend(pair.second);
			}
		} else if (cur.IsSequence()) {
			for (YAML::detail::iterator_value child : cur) {
				descend(child);
			}
		} else if (cur.IsScalar()) {
			cb(cur);
		}
	}

	void descend(YAML::Node &target) {
		if (std::find(seen.begin(), seen.end(), target) == seen.end()) {
			(*this)(target);
		}
	}

	std::vector<YAML::Node> seen;
	Callback cb;

	friend class yaml_helper;
};

/**
 * @brief An helper class for reading and editing YAML documents
 */
class yaml_helper
{
public:
	inline static const std::string configs_key = "configs_files";

	/**
	* Load the YAML document represented by the input string.
	*/
	void load_from_string(const std::string& input)
	{
		m_root = YAML::Load(input);
		pre_process_env_vars(m_root);
	}

	/**
	* Load the YAML document from the given file path.
	*/
	void load_from_file(const std::string& path, std::vector<std::string>& loaded_config_files)
	{
		loaded_config_files.clear();
		m_root = load_from_file_int(path, loaded_config_files);

		const auto ppath = std::filesystem::path(path);
		const auto config_folder = ppath.parent_path();
		// Parse files to be included
		std::vector<std::string> include_files;
		get_sequence<std::vector<std::string>>(include_files, configs_key);
		for(const std::string& include_file : include_files)
		{
			// If user specifies a relative include file,
			// make it relative to main config file folder,
			// instead of cwd.
			auto include_file_path = std::filesystem::path(include_file);
			if (!include_file_path.is_absolute())
			{
				include_file_path = config_folder / include_file;
			}
			if (include_file_path == ppath)
			{
				throw std::runtime_error(
					"Config error: '" + configs_key + "' directive tried to recursively include main config file: " + path + ".");
			}
			if (std::filesystem::exists(include_file_path))
			{
				if (std::filesystem::is_regular_file(include_file_path))
				{
					include_config_file(include_file_path.string(), loaded_config_files);
				}
				else if (std::filesystem::is_directory(include_file_path))
				{
					std::vector<std::string> v;
					const auto it_options = std::filesystem::directory_options::follow_directory_symlink
								| std::filesystem::directory_options::skip_permission_denied;
					for (auto const& dir_entry : std::filesystem::directory_iterator(include_file_path, it_options))
					{
						if (std::filesystem::is_regular_file(dir_entry.path()))
						{
							v.push_back(dir_entry.path().string());
						}
						// We don't support nested directories
						else
						{
							falco_logger::log(falco_logger::level::WARNING, "Included config file has wrong type: " + dir_entry.path().string());
						}
					}
					std::sort(v.begin(), v.end());
					for (const auto &f : v)
					{
						include_config_file(f, loaded_config_files);
					}
				}
				else
				{
					falco_logger::log(falco_logger::level::WARNING, "Included config entry has wrong type: " + include_file_path.string());
				}
			}
			else
			{
				falco_logger::log(falco_logger::level::WARNING, "Included config entry unexistent: " + include_file_path.string());
			}
		}
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
			return node.as<T>(default_value);
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

	YAML::Node load_from_file_int(const std::string& path, std::vector<std::string>& loaded_config_files)
	{
		auto root = YAML::LoadFile(path);
		pre_process_env_vars(root);
		loaded_config_files.push_back(path);
		return root;
	}

	void include_config_file(const std::string& include_file_path, std::vector<std::string>& loaded_config_files)
	{
		auto loaded_nodes = load_from_file_int(include_file_path, loaded_config_files);
		for(auto n : loaded_nodes)
		{
			/*
			 * To avoid recursion hell,
			 * we don't support `configs_files` directives from included config files
			 * (that use load_from_file_int recursively).
			 */
			const auto &key = n.first.Scalar();
			if (key == configs_key)
			{
				throw std::runtime_error(
					"Config error: '" + configs_key + "' directive in included config file " + include_file_path + ".");
			}
			// We allow to override keys.
			// We don't need to use `get_node()` here,
			// since key is a top-level one.
			m_root[key] = n.second;
		}
	}

	/*
	 * When loading a yaml file,
	 * we immediately pre process all scalar values through a visitor private API,
	 * and resolve any "${env_var}" to its value;
	 * moreover, any "$${str}" is resolved to simply "${str}".
	 */
	void pre_process_env_vars(YAML::Node& root)
	{
		yaml_visitor([](YAML::Node &scalar) {
				auto value = scalar.as<std::string>();
				auto start_pos = value.find('$');
				while (start_pos != std::string::npos)
				{
					auto substr = value.substr(start_pos);
					// Case 1 -> ${}
					if (substr.rfind("${", 0) == 0)
					{
						auto end_pos = substr.find('}');
						if (end_pos != std::string::npos)
						{
							// Eat "${" and "}" when getting the env var name
							auto env_str = substr.substr(2, end_pos - 2);
							const char* env_value = std::getenv(env_str.c_str()); // Get the environment variable value
							if(env_value)
							{
								// env variable name + "${}"
								value.replace(start_pos, env_str.length() + 3, env_value);
							}
							else
							{
								value.erase(start_pos, env_str.length() + 3);
							}
						}
						else
						{
							// There are no "}" chars anymore; just break leaving rest of value untouched.
							break;
						}
					}
					// Case 2 -> $${}
					else if (substr.rfind("$${", 0) == 0)
					{
						auto end_pos = substr.find('}');
						if (end_pos != std::string::npos)
						{
							// Consume first "$" token
							value.erase(start_pos, 1);
						}
						else
						{
							// There are no "}" chars anymore; just break leaving rest of value untouched.
							break;
						}
						start_pos++; // consume the second '$' token
					}
					else
					{
						start_pos += substr.length();
					}
					start_pos = value.find("$", start_pos);
				}
				scalar = value;
			})(root);
	}

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
