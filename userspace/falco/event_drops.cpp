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

#include "event_drops.h"
#include "falco_common.h"

syscall_evt_drop_mgr::syscall_evt_drop_mgr():
	m_num_syscall_evt_drops(0),
	m_num_actions(0),
	m_inspector(NULL),
	m_outputs(NULL),
	m_next_check_ts(0),
	m_simulate_drops(false),
	m_threshold(0)
{
}

syscall_evt_drop_mgr::~syscall_evt_drop_mgr()
{
}

void syscall_evt_drop_mgr::init(std::shared_ptr<sinsp> inspector,
				std::shared_ptr<falco_outputs> outputs,
				const syscall_evt_drop_actions &actions,
				double threshold,
				double rate,
				double max_tokens,
				bool simulate_drops)
{
	m_inspector = inspector;
	m_outputs = outputs;
	m_actions = actions;
	m_bucket.init(rate, max_tokens);
	m_threshold = threshold;

	m_inspector->get_capture_stats(&m_last_stats);

	m_simulate_drops = simulate_drops;
	if(m_simulate_drops)
	{
		m_threshold = 0;
	}
}

bool syscall_evt_drop_mgr::process_event(std::shared_ptr<sinsp> inspector, sinsp_evt *evt)
{
	if(m_next_check_ts == 0)
	{
		m_next_check_ts = evt->get_ts() + ONE_SECOND_IN_NS;
	}

	if(m_next_check_ts < evt->get_ts())
	{
		scap_stats stats, delta;

		m_next_check_ts = evt->get_ts() + ONE_SECOND_IN_NS;

		m_inspector->get_capture_stats(&stats);

		delta.n_evts = stats.n_evts - m_last_stats.n_evts;
		delta.n_drops = stats.n_drops - m_last_stats.n_drops;
		delta.n_drops_buffer = stats.n_drops_buffer - m_last_stats.n_drops_buffer;
		delta.n_drops_buffer_clone_fork_enter = stats.n_drops_buffer_clone_fork_enter - m_last_stats.n_drops_buffer_clone_fork_enter;
		delta.n_drops_buffer_clone_fork_exit = stats.n_drops_buffer_clone_fork_exit - m_last_stats.n_drops_buffer_clone_fork_exit;
		delta.n_drops_buffer_execve_enter = stats.n_drops_buffer_execve_enter - m_last_stats.n_drops_buffer_execve_enter;
		delta.n_drops_buffer_execve_exit = stats.n_drops_buffer_execve_exit - m_last_stats.n_drops_buffer_execve_exit;
		delta.n_drops_buffer_connect_enter = stats.n_drops_buffer_connect_enter - m_last_stats.n_drops_buffer_connect_enter;
		delta.n_drops_buffer_connect_exit = stats.n_drops_buffer_connect_exit - m_last_stats.n_drops_buffer_connect_exit;
		delta.n_drops_buffer_open_enter = stats.n_drops_buffer_open_enter - m_last_stats.n_drops_buffer_open_enter;
		delta.n_drops_buffer_open_exit = stats.n_drops_buffer_open_exit - m_last_stats.n_drops_buffer_open_exit;
		delta.n_drops_buffer_dir_file_enter = stats.n_drops_buffer_dir_file_enter - m_last_stats.n_drops_buffer_dir_file_enter;
		delta.n_drops_buffer_dir_file_exit = stats.n_drops_buffer_dir_file_exit - m_last_stats.n_drops_buffer_dir_file_exit;
		delta.n_drops_buffer_other_interest_enter = stats.n_drops_buffer_other_interest_enter - m_last_stats.n_drops_buffer_other_interest_enter;
		delta.n_drops_buffer_other_interest_exit = stats.n_drops_buffer_other_interest_exit - m_last_stats.n_drops_buffer_other_interest_exit;
		delta.n_drops_buffer_close_exit = stats.n_drops_buffer_close_exit - m_last_stats.n_drops_buffer_close_exit;
		delta.n_drops_buffer_proc_exit = stats.n_drops_buffer_proc_exit - m_last_stats.n_drops_buffer_proc_exit;
		delta.n_drops_scratch_map = stats.n_drops_scratch_map - m_last_stats.n_drops_scratch_map;
		delta.n_drops_pf = stats.n_drops_pf - m_last_stats.n_drops_pf;
		delta.n_drops_bug = stats.n_drops_bug - m_last_stats.n_drops_bug;
		delta.n_preemptions = stats.n_preemptions - m_last_stats.n_preemptions;
		delta.n_suppressed = stats.n_suppressed - m_last_stats.n_suppressed;
		delta.n_tids_suppressed = stats.n_tids_suppressed - m_last_stats.n_tids_suppressed;

		m_last_stats = stats;

		if(m_simulate_drops)
		{
			falco_logger::log(falco_logger::level::INFO, "Simulating syscall event drop");
			delta.n_drops++;
		}

		if(delta.n_drops > 0)
		{
			double ratio = delta.n_drops;
			// The `n_evts` always contains the `n_drops`.
			ratio /= delta.n_evts;

			// When simulating drops the threshold is always zero
			if(ratio > m_threshold)
			{
				m_num_syscall_evt_drops++;

				// There were new drops in the last second.
				// If the token bucket allows, perform actions.
				if(m_bucket.claim(1, evt->get_ts()))
				{
					m_num_actions++;

					return perform_actions(evt->get_ts(), delta, inspector->check_current_engine(BPF_ENGINE) || inspector->check_current_engine(MODERN_BPF_ENGINE));
				}
				else
				{
					falco_logger::log(falco_logger::level::DEBUG, "Syscall event drop but token bucket depleted, skipping actions");
				}
			}
		}
	}

	return true;
}

void syscall_evt_drop_mgr::print_stats()
{
	fprintf(stderr, "Syscall event drop monitoring:\n");
	fprintf(stderr, "   - event drop detected: %lu occurrences\n", m_num_syscall_evt_drops);
	fprintf(stderr, "   - num times actions taken: %lu\n", m_num_actions);
}

bool syscall_evt_drop_mgr::perform_actions(uint64_t now, const scap_stats &delta, bool bpf_enabled)
{
	std::string rule = "Falco internal: syscall event drop";
	std::string msg = rule + ". " + std::to_string(delta.n_drops) + " system calls dropped in last second.";

	for(auto &act : m_actions)
	{
		switch(act)
		{
		case syscall_evt_drop_action::DISREGARD:
			return true;

		case syscall_evt_drop_action::LOG:
			falco_logger::log(falco_logger::level::DEBUG, std::move(msg));
			return true;

		case syscall_evt_drop_action::ALERT:
		{
			nlohmann::json output_fields;
			output_fields["n_evts"] = std::to_string(delta.n_evts);		/* Total number of kernel side events actively traced (not including events discarded due to simple consumer mode in eBPF case). */
			output_fields["n_drops"] = std::to_string(delta.n_drops);		/* Number of all kernel side event drops out of n_evts. */
			output_fields["n_drops_buffer_total"] = std::to_string(delta.n_drops_buffer);		/* Total number of kernel side drops due to full buffer, includes all categories below, likely higher than sum of syscall categories. */
			/* Kernel side drops due to full buffer for categories of system calls. Not all system calls of interest are mapped into one of the categories.
			 * Insights:
			 *   (1) Identify statistical properties of workloads (e.g. ratios between categories).
			 *   (2) Data-driven optimization opportunity for kernel side filtering and prioritization.
			 *   (3) Response: Coarse grained insights into syscalls dropped.
			 *   (4) Bonus: Cost associated with syscall category (typically `open` system call category is highest by orders of magnitude).
			 */
			output_fields["n_drops_buffer_clone_fork_enter"] = std::to_string(delta.n_drops_buffer_clone_fork_enter);
			output_fields["n_drops_buffer_clone_fork_exit"] = std::to_string(delta.n_drops_buffer_clone_fork_exit);
			output_fields["n_drops_buffer_execve_enter"] = std::to_string(delta.n_drops_buffer_execve_enter);
			output_fields["n_drops_buffer_execve_exit"] = std::to_string(delta.n_drops_buffer_execve_exit);
			output_fields["n_drops_buffer_connect_enter"] = std::to_string(delta.n_drops_buffer_connect_enter);
			output_fields["n_drops_buffer_connect_exit"] = std::to_string(delta.n_drops_buffer_connect_exit);
			output_fields["n_drops_buffer_open_enter"] = std::to_string(delta.n_drops_buffer_open_enter);
			output_fields["n_drops_buffer_open_exit"] = std::to_string(delta.n_drops_buffer_open_exit);
			output_fields["n_drops_buffer_dir_file_enter"] = std::to_string(delta.n_drops_buffer_dir_file_enter);
			output_fields["n_drops_buffer_dir_file_exit"] = std::to_string(delta.n_drops_buffer_dir_file_exit);
			/* `n_drops_buffer_other_interest_*` Category consisting of other system calls of interest,
			 * not all other system calls that did not match a category from above.
			 * Ideal for a custom category if needed - simply patch switch statement in kernel driver code (`falcosecurity/libs` repo).
			 */
			output_fields["n_drops_buffer_other_interest_enter"] = std::to_string(delta.n_drops_buffer_other_interest_enter);
			output_fields["n_drops_buffer_other_interest_exit"] = std::to_string(delta.n_drops_buffer_other_interest_exit);
			output_fields["n_drops_buffer_close_exit"] = std::to_string(delta.n_drops_buffer_close_exit);
			output_fields["n_drops_buffer_proc_exit"] = std::to_string(delta.n_drops_buffer_proc_exit);
			output_fields["n_drops_scratch_map"] = std::to_string(delta.n_drops_scratch_map);		/* Number of kernel side scratch map drops. */
			output_fields["n_drops_page_faults"] = std::to_string(delta.n_drops_pf);		/* Number of kernel side page faults drops (invalid memory access). */
			output_fields["n_drops_bug"] = std::to_string(delta.n_drops_bug);		/* Number of kernel side bug drops (invalid condition in the kernel instrumentation). */
			output_fields["ebpf_enabled"] = std::to_string(bpf_enabled);
			m_outputs->handle_msg(now, falco_common::PRIORITY_DEBUG, msg, rule, output_fields);
			return true;
		}
		case syscall_evt_drop_action::EXIT:
			falco_logger::log(falco_logger::level::CRIT, std::move(msg));
			falco_logger::log(falco_logger::level::CRIT, "Exiting.");
			return false;

		default:
			falco_logger::log(falco_logger::level::ERR, "Ignoring unknown action " + std::to_string(int(act)));
			return true;
		}
	}

	return true;
}
