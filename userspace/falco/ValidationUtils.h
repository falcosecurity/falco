#pragma once

#include <string>
#include <unordered_set>
#include <yaml-cpp/yaml.h>

namespace valijson {
namespace adapters {

class YamlCppAdapter;

}  
}  

void validateKeysRecursive(const YAML::Node& node, const std::string& prefix, const std::unordered_set<std::string>& fixedSchemaKeys);
