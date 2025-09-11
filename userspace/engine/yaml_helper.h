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
#include <numeric>

#include <nlohmann/json.hpp>
#include <valijson/adapters/nlohmann_json_adapter.hpp>
#include <valijson/adapters/yaml_cpp_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>

class yaml_helper;

class yaml_visitor {
private:
	using Callback = std::function<void(YAML::Node&)>;
	explicit yaml_visitor(Callback cb): seen(), cb(std::move(cb)) {}

	void operator()(YAML::Node& cur) {
		seen.push_back(cur);
		if(cur.IsMap()) {
			for(YAML::detail::iterator_value pair : cur) {
				descend(pair.second);
			}
		} else if(cur.IsSequence()) {
			for(YAML::detail::iterator_value child : cur) {
				descend(child);
			}
		} else if(cur.IsScalar()) {
			cb(cur);
		}
	}

	void descend(YAML::Node& target) {
		if(std::find(seen.begin(), seen.end(), target) == seen.end()) {
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
class yaml_helper {
public:
	inline static const std::string configs_key = "config_files";
	inline static const std::string validation_ok = "ok";
	inline static const std::string validation_failed = "failed";
	inline static const std::string validation_none = "none";

	enum config_files_strategy {
		STRATEGY_APPEND,  // append to existing sequence keys, override scalar keys and add new ones
		STRATEGY_OVERRIDE,  // override existing keys (sequences too) and add new ones
		STRATEGY_ADDONLY    // only add new keys and ignore existing ones
	};

	static enum config_files_strategy strategy_from_string(const std::string& strategy) {
		if(strategy == "override") {
			return yaml_helper::STRATEGY_OVERRIDE;
		}
		if(strategy == "add-only") {
			return yaml_helper::STRATEGY_ADDONLY;
		}
		return yaml_helper::STRATEGY_APPEND;
	}

	static std::string strategy_to_string(const enum config_files_strategy strategy) {
		switch(strategy) {
		case yaml_helper::STRATEGY_OVERRIDE:
			return "override";
		case yaml_helper::STRATEGY_ADDONLY:
			return "add-only";
		default:
			return "append";
		}
	}

	/**
	 * Load all the YAML document represented by the input string.
	 * Since this is used by rule loader, does not process env vars.
	 */
	std::vector<YAML::Node> loadall_from_string(
	        const std::string& input,
	        const nlohmann::json& schema = {},
	        std::vector<std::string>* schema_warnings = nullptr) {
		auto nodes = YAML::LoadAll(input);
		if(schema_warnings) {
			schema_warnings->clear();
			if(!schema.empty()) {
				// Validate each node.
				for(const auto& node : nodes) {
					validate_node(node, schema, schema_warnings);
				}
			} else {
				schema_warnings->push_back(validation_none);
			}
		}
		return nodes;
	}

	/**
	 * Load the YAML document represented by the input string.
	 */
	void load_from_string(const std::string& input,
	                      const nlohmann::json& schema = {},
	                      std::vector<std::string>* schema_warnings = nullptr) {
		m_root = YAML::Load(input);
		pre_process_env_vars(m_root);

		if(schema_warnings) {
			schema_warnings->clear();
			if(!schema.empty()) {
				validate_node(m_root, schema, schema_warnings);
			} else {
				schema_warnings->push_back(validation_none);
			}
		}
	}

	/**
	 * Load the YAML document from the given file path.
	 */
	void load_from_file(const std::string& path,
	                    const nlohmann::json& schema = {},
	                    std::vector<std::string>* schema_warnings = nullptr) {
		m_root = load_from_file_int(path, schema, schema_warnings);
	}

	void include_config_file(const std::string& include_file_path,
	                         enum config_files_strategy strategy = STRATEGY_APPEND,
	                         const nlohmann::json& schema = {},
	                         std::vector<std::string>* schema_warnings = nullptr) {
		auto loaded_nodes = load_from_file_int(include_file_path, schema, schema_warnings);
		for(auto n : loaded_nodes) {
			/*
			 * To avoid recursion hell,
			 * we don't support `config_files` directives from included config files
			 * (that use load_from_file_int recursively).
			 */
			const auto& key = n.first.Scalar();
			if(key == configs_key) {
				throw std::runtime_error("Config error: '" + configs_key +
				                         "' directive in included config file " +
				                         include_file_path + ".");
			}
			switch(strategy) {
			case STRATEGY_APPEND:
				if(n.second.IsSequence()) {
					for(const auto& item : n.second) {
						m_root[key].push_back(item);
					}
					break;
				}
				// fallthrough
			case STRATEGY_OVERRIDE:
				m_root[key] = n.second;
				break;
			case STRATEGY_ADDONLY:
				if(!m_root[key].IsDefined()) {
					m_root[key] = n.second;
				}
				break;
			}
		}
	}

	/**
	 * Clears the internal loaded document.
	 */
	void clear() { m_root = YAML::Node(); }

	/**
	 * Get a scalar value from the node identified by key.
	 */
	template<typename T>
	const T get_scalar(const std::string& key, const T& default_value) const {
		YAML::Node node;
		get_node(node, key);
		if(node.IsDefined()) {
			return node.as<T>(default_value);
		}
		return default_value;
	}

	/**
	 * Set the node identified by key to value.
	 */
	template<typename T>
	void set_scalar(const std::string& key, const T& value) {
		YAML::Node node;
		get_node(node, key, true);
		node = value;
	}

	/**
	 * Set the node identified by key to an object value
	 */
	void set_object(const std::string& key, const YAML::Node& value) {
		YAML::Node node;
		get_node(node, key, true);
		node = value;
	}

	/**
	 * Get the sequence value from the node identified by key.
	 */
	template<typename T>
	void get_sequence(T& ret, const std::string& key) const {
		YAML::Node node;
		get_node(node, key);
		return get_sequence_from_node<T>(ret, node);
	}

	/**
	 * Return true if the node identified by key is defined.
	 */
	bool is_defined(const std::string& key) const {
		YAML::Node node;
		get_node(node, key);
		return node.IsDefined();
	}

	std::string dump() const {
		YAML::Emitter emitter;
		emitter << YAML::DoubleQuoted << YAML::Flow << YAML::LowerNull << YAML::BeginSeq << m_root;
		return emitter.c_str() + 1;  // drop initial '[' char
	}

private:
	YAML::Node m_root;

	YAML::Node load_from_file_int(const std::string& path,
	                              const nlohmann::json& schema,
	                              std::vector<std::string>* schema_warnings) {
		auto root = YAML::LoadFile(path);
		pre_process_env_vars(root);

		if(schema_warnings) {
			schema_warnings->clear();
			if(!schema.empty()) {
				validate_node(root, schema, schema_warnings);
			} else {
				schema_warnings->push_back(validation_none);
			}
		}
		return root;
	}

	void validate_node(const YAML::Node& node,
	                   const nlohmann::json& schema,
	                   std::vector<std::string>* schema_warnings) {
		// Validate the yaml against our json schema
		valijson::Schema schemaDef;
		valijson::SchemaParser schemaParser;
		valijson::Validator validator(valijson::Validator::kWeakTypes);
		valijson::ValidationResults validationResults;
		valijson::adapters::YamlCppAdapter configAdapter(node);
		valijson::adapters::NlohmannJsonAdapter schemaAdapter(schema);
		schemaParser.populateSchema(schemaAdapter, schemaDef);

		if(!validator.validate(schemaDef, configAdapter, &validationResults)) {
			valijson::ValidationResults::Error error;
			// report only the top-most error
			while(validationResults.popError(error)) {
				schema_warnings->push_back(std::string(validation_failed + " for ") +
				                           std::accumulate(error.context.begin(),
				                                           error.context.end(),
				                                           std::string("")) +
				                           ": " + error.description);
			}
		} else {
			schema_warnings->push_back(validation_ok);
		}
	}

	/*
	 * When loading a yaml file,
	 * we immediately pre process all scalar values through a visitor private API,
	 * and resolve any "${env_var}" to its value;
	 * moreover, any "$${str}" is resolved to simply "${str}".
	 */
	void pre_process_env_vars(YAML::Node& root) {
		yaml_visitor([](YAML::Node& scalar) {
			auto value = scalar.as<std::string>();
			auto start_pos = value.find('$');
			while(start_pos != std::string::npos) {
				auto substr = value.substr(start_pos);
				// Case 1 -> ${}
				if(substr.rfind("${", 0) == 0) {
					auto end_pos = substr.find('}');
					if(end_pos != std::string::npos) {
						// Eat "${" and "}" when getting the env var name
						auto env_str = substr.substr(2, end_pos - 2);
						const char* env_value =
						        std::getenv(env_str.c_str());  // Get the environment variable value
						if(env_value) {
							// env variable name + "${}"
							value.replace(start_pos, env_str.length() + 3, env_value);
						} else {
							value.erase(start_pos, env_str.length() + 3);
						}
					} else {
						// There are no "}" chars anymore; just break leaving rest of value
						// untouched.
						break;
					}
				}
				// Case 2 -> $${}
				else if(substr.rfind("$${", 0) == 0) {
					auto end_pos = substr.find('}');
					if(end_pos != std::string::npos) {
						// Consume first "$" token
						value.erase(start_pos, 1);
					} else {
						// There are no "}" chars anymore; just break leaving rest of value
						// untouched.
						break;
					}
					start_pos++;  // consume the second '$' token
				} else {
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
	 * NodeKey	:= (any)+ ('[' (integer)+? ']')*
	 *
	 * If can_append is true, an empty NodeKey will append a new entry
	 * to the sequence, it is rejected otherwise.
	 *
	 * Some examples of accepted key strings:
	 * - NodeName
	 * - ListValue[3].subvalue
	 * - MatrixValue[1][3]
	 * - value1.subvalue2.subvalue3
	 */
	void get_node(YAML::Node& ret, const std::string& key, bool can_append = false) const {
		try {
			std::string nodeKey;
			ret.reset(m_root);
			for(std::string::size_type i = 0; i < key.size(); ++i) {
				char c = key[i];
				bool should_shift = c == '.' || c == '[' || i == key.size() - 1;

				if(c != '.' && c != '[') {
					if(i > 0 && nodeKey.empty() && key[i - 1] != '.') {
						throw std::runtime_error("Parsing error: expected '.' character at pos " +
						                         std::to_string(i - 1));
					}
					nodeKey += c;
				}

				if(should_shift) {
					if(nodeKey.empty()) {
						throw std::runtime_error("Parsing error: unexpected character at pos " +
						                         std::to_string(i));
					}
					ret.reset(ret[nodeKey]);
					nodeKey.clear();
				}
				if(c == '[') {
					auto close_param_idx = key.find(']', i);
					std::string idx_str = key.substr(i + 1, close_param_idx - i - 1);
					int nodeIdx;

					bool ret_appendable = !ret.IsDefined() || ret.IsSequence();
					if(idx_str.empty() && ret_appendable && can_append) {
						YAML::Node newNode;
						ret.push_back(newNode);
						nodeIdx = ret.size() - 1;
					} else {
						try {
							nodeIdx = std::stoi(idx_str);
						} catch(const std::exception& e) {
							throw std::runtime_error(
							        "Parsing error: expected a numeric index, found '" + idx_str +
							        "'");
						}
					}
					ret.reset(ret[nodeIdx]);
					i = close_param_idx;
					if(i < key.size() - 1 && key[i + 1] == '.') {
						i++;
					}
				}
			}
		} catch(const std::exception& e) {
			throw std::runtime_error("Config error at key \"" + key +
			                         "\": " + std::string(e.what()));
		}
	}

	template<typename T>
	void get_sequence_from_node(T& ret, const YAML::Node& node) const {
		if(node.IsDefined()) {
			if(node.IsSequence()) {
				for(const YAML::Node& item : node) {
					ret.insert(ret.end(), item.as<typename T::value_type>());
				}
			} else if(node.IsScalar()) {
				ret.insert(ret.end(), node.as<typename T::value_type>());
			}
		}
	}
};

// define a yaml-cpp conversion function for nlohmann json objects
namespace YAML {
template<>
struct convert<nlohmann::json> {
	static bool decode(const Node& node, nlohmann::json& res) {
		switch(node.Type()) {
		case YAML::NodeType::Map:
			for(auto&& it : node) {
				nlohmann::json sub{};
				YAML::convert<nlohmann::json>::decode(it.second, sub);
				res[it.first.as<std::string>()] = sub;
			}
			break;
		case YAML::NodeType::Sequence:
			for(auto&& it : node) {
				nlohmann::json sub{};
				YAML::convert<nlohmann::json>::decode(it, sub);
				res.emplace_back(sub);
			}
			break;
		case YAML::NodeType::Scalar: {
			int int_val;
			double double_val;
			bool bool_val;
			std::string str_val;
			if(YAML::convert<int>::decode(node, int_val)) {
				res = int_val;
			} else if(YAML::convert<double>::decode(node, double_val)) {
				res = double_val;
			} else if(YAML::convert<bool>::decode(node, bool_val)) {
				res = bool_val;
			} else if(YAML::convert<std::string>::decode(node, str_val)) {
				res = str_val;
			}
		}
		default:
			break;
		}

		return true;
	}
	// The "encode" function is not needed here, in fact you can simply YAML::load any json string.
};
}  // namespace YAML
