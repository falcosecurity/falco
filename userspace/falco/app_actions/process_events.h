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

#include "run_action.h"

namespace falco {
namespace app {

class act_process_events : public run_action {
public:
	act_process_events(application &app);
	virtual ~act_process_events();

	const std::string &name() override;

	const std::list<std::string> &prerequsites() override;

	run_result run() override;

private:

#ifndef MINIMAL_BUILD
	void read_k8s_audit_trace_file(std::string &trace_filename);
#endif

	uint64_t do_inspect(std::shared_ptr<falco_engine> engine,
			    std::shared_ptr<falco_outputs> outputs,
			    std::shared_ptr<sinsp> inspector,
			    std::string &event_source,
			    std::shared_ptr<falco_configuration> config,
			    syscall_evt_drop_mgr &sdropmgr,
			    uint64_t duration_to_tot_ns,
			    string &stats_filename,
			    uint64_t stats_interval,
			    bool all_events,
			    run_result &result);

	std::string m_name;
	std::list<std::string> m_prerequsites;
};

}; // namespace application
}; // namespace falco

