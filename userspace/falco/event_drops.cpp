/*
Copyright (C) 2021 The Falco Authors.

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
#include "banned.h" // This raises a compilation error when certain functions are used

syscall_evt_drop_mgr::syscall_evt_drop_mgr():
	m_num_syscall_evt_drops(0),
	m_num_actions(0),
	m_inspector(NULL),
	m_outputs(NULL),
	m_next_check_ts(0),
	m_simulate_drops(false)
{
}

syscall_evt_drop_mgr::~syscall_evt_drop_mgr()
{
}

void syscall_evt_drop_mgr::init(sinsp *inspector,
				falco_outputs *outputs,
				syscall_evt_drop_actions &actions,
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

bool syscall_evt_drop_mgr::process_event(sinsp *inspector, sinsp_evt *evt)
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
		delta.n_drops_pf = stats.n_drops_pf - m_last_stats.n_drops_pf;
		delta.n_drops_bug = stats.n_drops_bug - m_last_stats.n_drops_bug;
		delta.n_preemptions = stats.n_preemptions - m_last_stats.n_preemptions;
		delta.n_suppressed = stats.n_suppressed - m_last_stats.n_suppressed;
		delta.n_tids_suppressed = stats.n_tids_suppressed - m_last_stats.n_tids_suppressed;

		m_last_stats = stats;

		if(m_simulate_drops)
		{
			falco_logger::log(LOG_INFO, "Simulating syscall event drop");
			delta.n_drops++;
		}

		if(m_simulate_drops || (delta.n_drops > 0 && delta.n_evts > 0))
		{
			double ratio = delta.n_drops;
			// Number of events can possiblity be zero here only when simulating drops
			// In which case, ratio holds an infinite value
			// Assuming IEC 559 (aka IEEE 754 - std::numeric_limits<T>::is_iec559) is true
			// Anyways, this is always greater than zero when not simulating drops
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

					return perform_actions(evt->get_ts(), delta, inspector->is_bpf_enabled());
				}
				else
				{
					falco_logger::log(LOG_DEBUG, "Syscall event drop but token bucket depleted, skipping actions");
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

bool syscall_evt_drop_mgr::perform_actions(uint64_t now, scap_stats &delta, bool bpf_enabled)
{
	std::string rule = "Falco internal: syscall event drop";
	std::string msg = rule + ". " + std::to_string(delta.n_drops) + " system calls dropped in last second.";

	bool should_exit = false;

	for(auto &act : m_actions)
	{
		switch(act)
		{
		case syscall_evt_drop_action::IGNORE:
			break;

		case syscall_evt_drop_action::LOG:
			falco_logger::log(LOG_ERR, msg);
			break;

		case syscall_evt_drop_action::ALERT:
		{
			std::map<std::string, std::string> output_fields;
			output_fields["n_evts"] = std::to_string(delta.n_evts);
			output_fields["n_drops"] = std::to_string(delta.n_drops);
			output_fields["n_drops_buffer"] = std::to_string(delta.n_drops_buffer);
			output_fields["n_drops_pf"] = std::to_string(delta.n_drops_pf);
			output_fields["n_drops_bug"] = std::to_string(delta.n_drops_bug);
			output_fields["ebpf_enabled"] = std::to_string(bpf_enabled);
			m_outputs->handle_msg(now, falco_common::PRIORITY_CRITICAL, msg, rule, output_fields);
			break;
		}
		case syscall_evt_drop_action::EXIT:
			should_exit = true;
			break;

		default:
			falco_logger::log(LOG_ERR, "Ignoring unknown action " + std::to_string(int(act)));
			break;
		}
	}

	if(should_exit)
	{
		falco_logger::log(LOG_CRIT, msg);
		falco_logger::log(LOG_CRIT, "Exiting.");
		return false;
	}

	return true;
}
