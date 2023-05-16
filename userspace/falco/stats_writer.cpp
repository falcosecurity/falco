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

#include <sys/time.h>
#include <signal.h>
#include <nlohmann/json.hpp>
#include <atomic>

#include <nlohmann/json.hpp>

#include "falco_common.h"
#include "stats_writer.h"
#include "logger.h"
#include "banned.h" // This raises a compilation error when certain functions are used
#include "config_falco.h"
#include <re2/re2.h>

// note: ticker_t is an uint16_t, which is enough because we don't care about
// overflows here. Threads calling stats_writer::handle() will just
// check that this value changed since their last observation.
static std::atomic<stats_writer::ticker_t> s_timer((stats_writer::ticker_t) 0);

static void timer_handler(int signum)
{
	s_timer.fetch_add(1, std::memory_order_relaxed);
}

bool stats_writer::init_ticker(uint32_t interval_msec, std::string &err)
{
	struct itimerval timer;
	struct sigaction handler;

	memset (&handler, 0, sizeof (handler));
	handler.sa_handler = &timer_handler;
	if (sigaction(SIGALRM, &handler, NULL) == -1)
	{
		err = std::string("Could not set up signal handler for periodic timer: ") + strerror(errno);
		return false;
	}

	timer.it_value.tv_sec = interval_msec / 1000;
	timer.it_value.tv_usec = (interval_msec % 1000) * 1000;
	timer.it_interval = timer.it_value;
	if (setitimer(ITIMER_REAL, &timer, NULL) == -1)
	{
		err = std::string("Could not set up periodic timer: ") + strerror(errno);
		return false;
	}

	return true;
}

stats_writer::ticker_t stats_writer::get_ticker()
{
	return s_timer.load(std::memory_order_relaxed);
}

stats_writer::stats_writer(std::shared_ptr<falco_outputs> outputs, std::shared_ptr<falco_configuration> config)
	: m_initialized(false), m_total_samples(0)
{
	m_outputs = outputs;
	m_config = config;
}

stats_writer::stats_writer(const std::string &filename, std::shared_ptr<falco_outputs> outputs, std::shared_ptr<falco_configuration> config)
	: m_initialized(true), m_total_samples(0)
{
	m_output.exceptions(std::ofstream::failbit | std::ofstream::badbit);
	m_output.open(filename, std::ios_base::app);
	m_worker = std::thread(&stats_writer::worker, this);
	m_outputs = outputs;
	m_config = config;
}

stats_writer::~stats_writer()
{
	if (m_initialized)
	{
		stop_worker();
		m_output.close();
	}
}

bool stats_writer::has_output() const
{
	return m_initialized;
}

void stats_writer::stop_worker()
{
	stats_writer::msg msg;
	msg.stop = true;
	push(msg);
	if(m_worker.joinable())
	{
		m_worker.join();
	}
}

inline void stats_writer::push(const stats_writer::msg& m)
{
	if (!m_queue.try_push(m))
	{
		fprintf(stderr, "Fatal error: Stats queue reached maximum capacity. Exiting.\n");
		exit(EXIT_FAILURE);
	}
}

void stats_writer::worker() noexcept
{
	stats_writer::msg m;
	nlohmann::json jmsg;
	auto tick = stats_writer::get_ticker();
	auto last_tick = tick;

	while(true)
	{
		// blocks until a message becomes availables
		m_queue.pop(m);
		if (m.stop)
		{
			return;
		}
		
		tick = stats_writer::get_ticker();
		if (last_tick != tick)
		{
			m_total_samples++;
			try
			{
				jmsg["sample"] = m_total_samples;
				jmsg["output_fields"] = m.output_fields;
				m_output << jmsg.dump() << std::endl;
			}
			catch(const std::exception &e)
			{
				falco_logger::log(LOG_ERR, "stats_writer (worker): " + std::string(e.what()) + "\n");
			}
		}
	}
}

stats_writer::collector::collector(std::shared_ptr<stats_writer> writer)
	: m_writer(writer), m_last_tick(0), m_samples(0), m_last_now(0), m_last_n_evts(0), m_last_n_drops(0), m_last_num_evts(0)
{
}

std::map<std::string, std::string> stats_writer::collector::get_metrics_output_fields_wrapper(std::shared_ptr<sinsp> inspector, uint64_t now, std::string src, uint64_t num_evts, double stats_snapshot_time_delta_sec)
{
	std::map<std::string, std::string> output_fields;
	const scap_agent_info* agent_info = inspector->get_agent_info();
	const scap_machine_info* machine_info = inspector->get_machine_info();

	/* Wrapper fields useful for statistical analyses and attributions. Always enabled. */
	output_fields["evt.time"] = std::to_string(now); /* Some ETLs may prefer a consistent timestamp within output_fields. */
	output_fields["falco_version"] = FALCO_VERSION;
	output_fields["falco_start_ts"] = std::to_string(agent_info->start_ts_epoch);
	output_fields["kernel_release"] = agent_info->uname_r;
	output_fields["host_boot_ts"] = std::to_string(machine_info->boot_ts_epoch);
	output_fields["hostname"] = machine_info->hostname; /* Explicitly add hostname to log msg in case hostname rule output field is disabled. */
	output_fields["host_num_cpus"] = std::to_string(machine_info->num_cpus);
	if (inspector->check_current_engine(BPF_ENGINE))
	{
		output_fields["driver"] = "bpf";
	}
	else if (inspector->check_current_engine(MODERN_BPF_ENGINE))
	{
		output_fields["driver"] = "modern_bpf";
	}
	else if (inspector->check_current_engine(KMOD_ENGINE))
	{
		output_fields["driver"] = "kmod";
	}
	else
	{
		output_fields["driver"] = "no_driver";
	}
	output_fields["src"] = src;

	/* Falco userspace event counters. Always enabled. */
	if (m_last_num_evts != 0 && stats_snapshot_time_delta_sec > 0)
	{
		/* Successfully processed userspace event rate. */
		output_fields["falco_evts_rate_sec"] = std::to_string((num_evts - m_last_num_evts) / (double)stats_snapshot_time_delta_sec);
	}
	output_fields["falco_num_evts"] = std::to_string(num_evts);
	output_fields["falco_num_evts_prev"] = std::to_string(m_last_num_evts);
	m_last_num_evts = num_evts;

	return output_fields;

}

std::map<std::string, std::string> stats_writer::collector::get_metrics_output_fields_additional(std::shared_ptr<sinsp> inspector, std::map<std::string, std::string> output_fields, double stats_snapshot_time_delta_sec, std::string src)
{
	const scap_agent_info* agent_info = inspector->get_agent_info();
	const scap_machine_info* machine_info = inspector->get_machine_info();

#ifndef MINIMAL_BUILD
	/* Resource utilization, CPU and memory usage etc. */
	uint32_t nstats = 0;
	int32_t rc = 0;
	if (m_writer->m_config->m_metrics_resource_utilization_enabled)
	{
		const scap_stats_v2* utilization;
		auto buffer = inspector->get_sinsp_stats_v2_buffer();
		utilization = libsinsp::resource_utilization::get_resource_utilization(agent_info, buffer, &nstats, &rc);
		if (utilization && rc == 0 && nstats > 0)
		{
			// todo: support unit conversions for memory metrics
			for(uint32_t stat = 0; stat < nstats; stat++)
			{
				switch(utilization[stat].type)
				{
				case STATS_VALUE_TYPE_U64:
					if (m_writer->m_config->m_metrics_convert_memory_to_mb && strncmp(utilization[stat].name, "container_memory_used", 21) == 0)
					{
						output_fields[utilization[stat].name] = std::to_string(utilization[stat].value.u64 / (double)1024 / (double)1024);
					}
					else
					{
						output_fields[utilization[stat].name] = std::to_string(utilization[stat].value.u64);
					}
					break;
				case STATS_VALUE_TYPE_U32:
					if (m_writer->m_config->m_metrics_convert_memory_to_mb && strncmp(utilization[stat].name, "memory_", 7) == 0)
					{
						output_fields[utilization[stat].name] = std::to_string(utilization[stat].value.u32 / (double)1024);
					}
					else
					{
						output_fields[utilization[stat].name] = std::to_string(utilization[stat].value.u32);
					}
					break;
				case STATS_VALUE_TYPE_D:
					output_fields[utilization[stat].name] = std::to_string(utilization[stat].value.d);
					break;
				default:
					break;
				}
			}
		}
	}

	if (src != falco_common::syscall_source)
	{
		return output_fields;
	}

	/* Kernel side stats counters and libbpf stats if applicable. */
	nstats = 0;
	rc = 0;
	uint32_t flags = 0;

	if (m_writer->m_config->m_metrics_kernel_event_counters_enabled)
	{
		flags |= PPM_SCAP_STATS_KERNEL_COUNTERS;
	}
	if (m_writer->m_config->m_metrics_libbpf_stats_enabled && !inspector->check_current_engine(KMOD_ENGINE) && (machine_info->flags & PPM_BPF_STATS_ENABLED))
	{
		flags |= PPM_SCAP_STATS_LIBBPF_STATS;
	}
	const scap_stats_v2* stats_v2 = inspector->get_capture_stats_v2(flags, &nstats, &rc);
	if (stats_v2 && nstats > 0 && rc == 0)
	{
		for(uint32_t stat = 0; stat < nstats; stat++)
		{
			switch(stats_v2[stat].type)
			{
			case STATS_VALUE_TYPE_U64:
				if (strncmp(stats_v2[stat].name, "n_evts", 6) == 0)
				{
					output_fields["falco_evts_rate_kernel_sec"] = std::to_string(0);
					if (m_last_n_evts != 0 && stats_snapshot_time_delta_sec > 0)
					{
						/* n_evts is total number of kernel side events. */
						output_fields["falco_evts_rate_kernel_sec"] = std::to_string((stats_v2[stat].value.u64 - m_last_n_evts) / stats_snapshot_time_delta_sec);
					}
					output_fields["n_evts_prev"] = std::to_string(m_last_n_evts);
					m_last_n_evts = stats_v2[stat].value.u64;
				}
				else if (strncmp(stats_v2[stat].name, "n_drops", 7) == 0)
				{
					output_fields["falco_evts_drop_rate_kernel_sec"] = std::to_string(0);
					if (m_last_n_drops != 0 && stats_snapshot_time_delta_sec > 0)
					{
						/* n_drops is total number of kernel side event drops. */
						output_fields["falco_evts_drop_rate_kernel_sec"] = std::to_string((stats_v2[stat].value.u64 - m_last_n_evts) / stats_snapshot_time_delta_sec);
					}
					output_fields["n_drops_prev"] = std::to_string(m_last_n_drops);
					m_last_n_drops = stats_v2[stat].value.u64;
				}
				output_fields[stats_v2[stat].name] = std::to_string(stats_v2[stat].value.u64);
				break;
			default:
				break;
			}
		}
	}
#endif

	return output_fields;
}

void stats_writer::collector::collect(std::shared_ptr<sinsp> inspector, const std::string &src, uint64_t num_evts)
{
	if (m_writer->m_config->m_metrics_enabled || m_writer->has_output())
	{
		/* Collect stats / metrics once per ticker period. */
		auto tick = stats_writer::get_ticker();
		if (tick != m_last_tick)
		{
			auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			uint64_t stats_snapshot_time_delta = 0;
			if (m_last_now != 0)
			{
				stats_snapshot_time_delta = now - m_last_now;
			}
			m_last_now = now;
			double stats_snapshot_time_delta_sec = (stats_snapshot_time_delta / (double)ONE_SECOND_IN_NS);

			/* Get respective metrics output_fields. */
			std::map<std::string, std::string> output_fields = stats_writer::collector::get_metrics_output_fields_wrapper(inspector, now, src, num_evts, stats_snapshot_time_delta_sec);
			output_fields = stats_writer::collector::get_metrics_output_fields_additional(inspector, output_fields, stats_snapshot_time_delta_sec, src);

			/* Pipe to respective output. */
			if (m_writer->m_config->m_metrics_enabled && m_writer->m_config->m_metrics_stats_rule_enabled && m_writer->m_outputs)
			{
				std::string rule = "Falco internal: resource utilization stats metrics";
				std::string msg = "";
				m_writer->m_outputs->handle_msg(now, falco_common::PRIORITY_INFORMATIONAL, msg, rule, output_fields);
			}
			if (m_writer->has_output())
			{
				stats_writer::msg msg;
				msg.output_fields = output_fields;
				m_writer->push(msg);
			}
			m_last_tick = tick;
		}
	}
}
