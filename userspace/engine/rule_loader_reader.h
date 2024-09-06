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

#include "rule_loader.h"
#include "rule_loader_collector.h"
#include <libsinsp/logger.h>
#include <libsinsp/version.h>
#include "falco_engine_version.h"

namespace rule_loader
{

/*!
    \brief Reads the contents of a ruleset
*/
class reader
{
public:
    reader() = default;
    virtual ~reader() = default;
    reader(reader&&) = default;
	reader& operator = (reader&&) = default;
	reader(const reader&) = default;
	reader& operator = (const reader&) = default;

    /*!
		\brief Reads the contents of a ruleset and uses a collector to store
        thew new definitions
	*/
	virtual bool read(configuration& cfg, collector& loader, const nlohmann::json& schema={});
    
    /*!
        \brief Engine version used to be represented as a simple progressive
	    number. With the new semver schema, the number now represents
	    the semver minor number. This function converts the legacy version 
	    number to the new semver schema.
    */
	static inline sinsp_version get_implicit_engine_version(uint32_t minor)
	{
		return sinsp_version(std::to_string(FALCO_ENGINE_VERSION_MAJOR) + "."
			+ std::to_string(minor) + "." 
			+ std::to_string(FALCO_ENGINE_VERSION_PATCH));
	}

	template <typename T>
	static void decode_val(const YAML::Node& item, const char *key, T& out, const rule_loader::context& ctx);

	template <typename T>
	static void decode_optional_val(const YAML::Node& item, const char *key, T& out, const rule_loader::context& ctx);

protected:

	virtual void read_item(rule_loader::configuration& cfg,
			       rule_loader::collector& collector,
			       const YAML::Node& item,
			       const rule_loader::context& parent);
};

}; // namespace rule_loader
