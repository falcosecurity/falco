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

#include <memory>
#include <unordered_set>

#include <libsinsp/sinsp.h>
#include <libsinsp/token_bucket.h>

#include "logger.h"
#include "falco_outputs.h"

// The possible actions that this class can take upon
// detecting a syscall event drop.
enum class syscall_evt_drop_action : uint8_t
{
	DISREGARD = 0,
	LOG,
	ALERT,
	EXIT
};

using syscall_evt_drop_actions = std::unordered_set<syscall_evt_drop_action>;

class syscall_evt_drop_mgr
{
public:
	syscall_evt_drop_mgr();
	virtual ~syscall_evt_drop_mgr();

	void init(std::shared_ptr<sinsp> inspector,
		  std::shared_ptr<falco_outputs> outputs,
		  const syscall_evt_drop_actions &actions,
		  double threshold,
		  double rate,
		  double max_tokens,
		  bool simulate_drops);

	// Call this for every event. The class will take care of
	// periodically measuring the scap stats, looking for syscall
	// event drops, and performing any actions.
	//
	// Returns whether event processing should continue or stop (with an error).
	bool process_event(std::shared_ptr<sinsp> inspector, sinsp_evt *evt);

	void print_stats();

protected:
	// Perform all configured actions.
	bool perform_actions(uint64_t now, const scap_stats &delta, bool bpf_enabled);

	uint64_t m_num_syscall_evt_drops;
	uint64_t m_num_actions;
	std::shared_ptr<sinsp> m_inspector;
	std::shared_ptr<falco_outputs> m_outputs;
	syscall_evt_drop_actions m_actions;
	token_bucket m_bucket;
	uint64_t m_next_check_ts;
	scap_stats m_last_stats;
	bool m_simulate_drops;
	double m_threshold;
};
