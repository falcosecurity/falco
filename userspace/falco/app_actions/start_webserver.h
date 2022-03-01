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

#include "init_action.h"

#ifndef MINIMAL_BUILD
#include "webserver.h"

namespace falco {
namespace app {

class act_start_webserver : public init_action {
public:
	act_start_webserver(application &app);
	virtual ~act_start_webserver();

	const std::string &name() override;

	const std::list<std::string> &prerequsites() override;

	run_result run() override;

	void deinit() override;

private:
	falco_webserver m_webserver;
	std::string m_name;
	std::list<std::string> m_prerequsites;
};

}; // namespace application
}; // namespace falco

#endif
