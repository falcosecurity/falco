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

#include <string>
#include <map>
#include "falco_engine.h"

class falco_formats
{
public:
	falco_formats(std::shared_ptr<const falco_engine> engine,
		      bool json_include_output_property,
		      bool json_include_tags_property);
	virtual ~falco_formats();

	std::string format_event(sinsp_evt *evt, const std::string &rule, const std::string &source,
				 const std::string &level, const std::string &format, const std::set<std::string> &tags,
				 const std::string &hostname) const;

	std::map<std::string, std::string> get_field_values(sinsp_evt *evt, const std::string &source,
					     const std::string &format) const ;

protected:
	std::shared_ptr<const falco_engine> m_falco_engine;
	bool m_json_include_output_property;
	bool m_json_include_tags_property;
};
