/*
Copyright (C) 2022 The Falco Authors.

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

#include "easyopts_action.h"

namespace falco {
namespace app {

class act_print_version : public easyopts_action {
public:
	act_print_version(application &app);
	virtual ~act_print_version();

	const std::string &name() override;

	const std::list<std::string> &prerequsites() override;

	run_result run() override;

private:
	std::string m_name;
	std::list<std::string> m_prerequsites;
};

}; // namespace application
}; // namespace falco

