/*
Copyright (C) 2016-2019 Draios Inc dba Sysdig.

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

#include <list>
#include <utility>
#include <string>

#include <yaml-cpp/yaml.h>
#include <nlohmann/json.hpp>

#pragma once

// This class parses a K8s Pod Security Policy (psp) and embeds a
// templating engine that can be used with a rules template to result
// in a set of falco rules that detects violations of the psp.

namespace falco
{

class k8s_psp_converter
{
public:
	k8s_psp_converter();
	virtual ~k8s_psp_converter();

	std::string generate_rules(const std::string &psp_yaml, const std::string &rules_template);

private:

	typedef std::list<std::pair<int64_t, int64_t>> ranges_t;

	// This holds all the data sent to the template engine. It's
	// filled in while parsing the psp yaml.
	nlohmann::json m_params;

	void init_params(nlohmann::json &params);

	nlohmann::json parse_ranges(const YAML::Node &node, bool create_objs=false);

	nlohmann::json parse_sequence(const YAML::Node &node);

        // Load the provided psp, populating this object with template
        // params. Throws falco_exception on error.
	void load_yaml(const std::string &psp_yaml);

};

};
