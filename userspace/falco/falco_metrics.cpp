// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <re2/re2.h>

#include "falco_metrics.h"

#include "app/state.h"

#include <libsinsp/sinsp.h>

#ifdef HAS_JEMALLOC
#include <jemalloc.h>
#endif

namespace fs = std::filesystem;

/*!
    \class falco_metrics
    \brief This class is used to convert the metrics provided by the application
    and falco libs into a string to be return by the metrics endpoint.
*/

/*!
    \brief content_type to be returned by the webserver's metrics endpoint.

    Currently it is the default Prometheus exposition format

    https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format
*/
const std::string falco_metrics::content_type = "text/plain; version=0.0.4";

/*!
    \brief this method takes an application \c state and returns a textual representation of
    its configured metrics.

    The current implementation returns a Prometheus exposition formatted string.
*/
std::string falco_metrics::to_text(const falco::app::state& state) {
	static const char* all_driver_engines[] = {BPF_ENGINE,
	                                           KMOD_ENGINE,
	                                           MODERN_BPF_ENGINE,
	                                           SOURCE_PLUGIN_ENGINE,
	                                           NODRIVER_ENGINE,
	                                           GVISOR_ENGINE};

	std::vector<std::shared_ptr<sinsp>> inspectors;
	std::vector<libs::metrics::libs_metrics_collector> metrics_collectors;

	for(const auto& source : state.enabled_sources) {
		auto source_info = state.source_infos.at(source);
		auto source_inspector = source_info->inspector;
		inspectors.emplace_back(source_inspector);
		metrics_collectors.emplace_back(
		        libs::metrics::libs_metrics_collector(source_inspector.get(),
		                                              state.config->m_metrics_flags));
	}
	libs::metrics::prometheus_metrics_converter prometheus_metrics_converter;
	std::string prometheus_text;

	for(auto inspector : inspectors) {
		// Falco wrapper metrics
		//
		for(size_t i = 0; i < sizeof(all_driver_engines) / sizeof(const char*); i++) {
			if(inspector->check_current_engine(all_driver_engines[i])) {
				prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
				        "engine_name",
				        "falcosecurity",
				        "scap",
				        {{"engine_name", all_driver_engines[i]}});
				break;
			}
		}

		const scap_agent_info* agent_info = inspector->get_agent_info();
		const scap_machine_info* machine_info = inspector->get_machine_info();
		libs::metrics::libs_metrics_collector libs_metrics_collector(inspector.get(), 0);
		prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
		        "version",
		        "falcosecurity",
		        "falco",
		        {{"version", FALCO_VERSION}});

		// Not all scap engines report agent and machine infos.
		if(agent_info) {
			prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
			        "kernel_release",
			        "falcosecurity",
			        "falco",
			        {{"kernel_release", agent_info->uname_r}});
		}
		if(machine_info) {
			prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
			        "hostname",
			        "falcosecurity",
			        "evt",
			        {{"hostname", machine_info->hostname}});
		}

#if defined(__linux__) and !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
		// Distinguish between config and rules files using labels, following Prometheus best
		// practices: https://prometheus.io/docs/practices/naming/#labels
		for(const auto& item : state.config.get()->m_loaded_rules_filenames_sha256sum) {
			fs::path fs_path = item.first;
			prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
			        "sha256_rules_files",
			        "falcosecurity",
			        "falco",
			        {{"file_name", fs_path.filename()}, {"sha256", item.second}});
		}

		for(const auto& item : state.config.get()->m_loaded_configs_filenames_sha256sum) {
			fs::path fs_path = item.first;
			prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
			        "sha256_config_files",
			        "falcosecurity",
			        "falco",
			        {{"file_name", fs_path.filename()}, {"sha256", item.second}});
		}

#endif

		for(const std::string& source : inspector->event_sources()) {
			prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
			        "evt_source",
			        "falcosecurity",
			        "falco",
			        {{"evt_source", source}});
		}
		std::vector<metrics_v2> additional_wrapper_metrics;

		if(agent_info) {
			additional_wrapper_metrics.emplace_back(libs::metrics::libsinsp_metrics::new_metric(
			        "start_ts",
			        METRICS_V2_MISC,
			        METRIC_VALUE_TYPE_U64,
			        METRIC_VALUE_UNIT_TIME_TIMESTAMP_NS,
			        METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
			        agent_info->start_ts_epoch));
		}
		if(machine_info) {
			additional_wrapper_metrics.emplace_back(libs::metrics::libsinsp_metrics::new_metric(
			        "host_boot_ts",
			        METRICS_V2_MISC,
			        METRIC_VALUE_TYPE_U64,
			        METRIC_VALUE_UNIT_TIME_TIMESTAMP_NS,
			        METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
			        machine_info->boot_ts_epoch));
			additional_wrapper_metrics.emplace_back(libs::metrics::libsinsp_metrics::new_metric(
			        "host_num_cpus",
			        METRICS_V2_MISC,
			        METRIC_VALUE_TYPE_U32,
			        METRIC_VALUE_UNIT_COUNT,
			        METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
			        machine_info->num_cpus));
		}
		additional_wrapper_metrics.emplace_back(libs::metrics::libsinsp_metrics::new_metric(
		        "outputs_queue_num_drops",
		        METRICS_V2_MISC,
		        METRIC_VALUE_TYPE_U64,
		        METRIC_VALUE_UNIT_COUNT,
		        METRIC_VALUE_METRIC_TYPE_MONOTONIC,
		        state.outputs->get_outputs_queue_num_drops()));

		if(agent_info) {
			auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
			                   std::chrono::system_clock::now().time_since_epoch())
			                   .count();
			additional_wrapper_metrics.emplace_back(libs::metrics::libsinsp_metrics::new_metric(
			        "duration_sec",
			        METRICS_V2_MISC,
			        METRIC_VALUE_TYPE_U64,
			        METRIC_VALUE_UNIT_TIME_S_COUNT,
			        METRIC_VALUE_METRIC_TYPE_MONOTONIC,
			        (uint64_t)((now - agent_info->start_ts_epoch) / ONE_SECOND_IN_NS)));
		}

		for(auto metric : additional_wrapper_metrics) {
			prometheus_metrics_converter.convert_metric_to_unit_convention(metric);
			prometheus_text +=
			        prometheus_metrics_converter.convert_metric_to_text_prometheus(metric,
			                                                                       "falcosecurity",
			                                                                       "falco");
		}

		// Falco metrics categories
		//
		// rules_counters_enabled
		if(state.config->m_metrics_flags & METRICS_V2_RULE_COUNTERS) {
			const stats_manager& rule_stats_manager = state.engine->get_rule_stats_manager();
			const indexed_vector<falco_rule>& rules = state.engine->get_rules();
			const std::vector<std::unique_ptr<std::atomic<uint64_t>>>& rules_by_id =
			        rule_stats_manager.get_by_rule_id();
			// Distinguish between rules counters using labels, following Prometheus best practices:
			// https://prometheus.io/docs/practices/naming/#labels
			for(size_t i = 0; i < rules_by_id.size(); i++) {
				auto rule = rules.at(i);
				auto count = rules_by_id[i]->load();
				if(count > 0) {
					/* Examples ...
					    # HELP falcosecurity_falco_rules_matches_total
					   https://falco.org/docs/metrics/ # TYPE
					   falcosecurity_falco_rules_matches_total counter
					    falcosecurity_falco_rules_matches_total{priority="4",rule_name="Read
					   sensitive file
					   untrusted",source="syscall",tag_T1555="true",tag_container="true",tag_filesystem="true",tag_host="true",tag_maturity_stable="true",tag_mitre_credential_access="true"}
					   10 # HELP falcosecurity_falco_rules_matches_total
					   https://falco.org/docs/metrics/ # TYPE
					   falcosecurity_falco_rules_matches_total counter
					    falcosecurity_falco_rules_matches_total{priority="5",rule_name="Unexpected
					   UDP
					   Traffic",source="syscall",tag_TA0011="true",tag_container="true",tag_host="true",tag_maturity_incubating="true",tag_mitre_exfiltration="true",tag_network="true"}
					   1
					*/
					auto metric = libs::metrics::libsinsp_metrics::new_metric(
					        "rules_matches",
					        METRICS_V2_RULE_COUNTERS,
					        METRIC_VALUE_TYPE_U64,
					        METRIC_VALUE_UNIT_COUNT,
					        METRIC_VALUE_METRIC_TYPE_MONOTONIC,
					        rules_by_id[i]->load());
					prometheus_metrics_converter.convert_metric_to_unit_convention(metric);
					std::map<std::string, std::string> const_labels = {
					        {"rule_name", rule->name},
					        {"priority", std::to_string(rule->priority)},
					        {"source", rule->source},
					};
					std::for_each(rule->tags.cbegin(),
					              rule->tags.cend(),
					              [&const_labels](std::string const& tag) {
						              const_labels.emplace(std::string{"tag_"} + tag, "true");
					              });
					prometheus_text +=
					        prometheus_metrics_converter.convert_metric_to_text_prometheus(
					                metric,
					                "falcosecurity",
					                "falco",
					                const_labels);
				}
			}
		}
#ifdef HAS_JEMALLOC
		if(state.config->m_metrics_flags & METRICS_V2_JEMALLOC_STATS) {
			nlohmann::json j;
			malloc_stats_print(
			        [](void* to, const char* from) {
				        nlohmann::json* j = (nlohmann::json*)to;
				        *j = nlohmann::json::parse(from);
			        },
			        &j,
			        "Jmdablxeg");
			const auto& j_stats = j["jemalloc"]["stats"];
			for(auto it = j_stats.begin(); it != j_stats.end(); ++it) {
				if(it.value().is_number_unsigned()) {
					std::uint64_t val = it.value().template get<std::uint64_t>();
					std::string key = "jemalloc." + it.key();
					auto metric = libs::metrics::libsinsp_metrics::new_metric(
					        key.c_str(),
					        METRICS_V2_JEMALLOC_STATS,
					        METRIC_VALUE_TYPE_U64,
					        METRIC_VALUE_UNIT_MEMORY_BYTES,
					        METRIC_VALUE_METRIC_TYPE_MONOTONIC,
					        val);
					prometheus_metrics_converter.convert_metric_to_unit_convention(metric);
					prometheus_text +=
					        prometheus_metrics_converter.convert_metric_to_text_prometheus(
					                metric,
					                "falcosecurity",
					                "falco");
				}
			}
		}
#endif
	}

	// Libs metrics categories
	//
	// resource_utilization_enabled
	// state_counters_enabled
	// kernel_event_counters_enabled
	// libbpf_stats_enabled
	for(auto metrics_collector : metrics_collectors) {
		metrics_collector.snapshot();
		auto metrics_snapshot = metrics_collector.get_metrics();

		for(auto& metric : metrics_snapshot) {
			prometheus_metrics_converter.convert_metric_to_unit_convention(metric);
			std::string prometheus_subsystem = "scap";

			if(metric.flags & METRICS_V2_RESOURCE_UTILIZATION) {
				prometheus_subsystem = "falco";
			}

			if(metric.flags & METRICS_V2_PLUGINS) {
				prometheus_subsystem = "plugins";
			}

			// raw incoming in form of for example n_evts_cpu_15 or n_drops_cpu_15
			if(strncmp(metric.name, "n_evts_cpu", 10) == 0 ||
			   strncmp(metric.name, "n_drops_cpu", 11) == 0)  // prefix match
			{
				std::string name_str(metric.name);
				re2::RE2 pattern("(\\d+)");
				std::string cpu_number;
				if(re2::RE2::PartialMatch(name_str, pattern, &cpu_number)) {
					re2::RE2::GlobalReplace(&name_str, pattern, "");
					// possible double __ will be sanitized within libs
					auto metric_new = libs::metrics::libsinsp_metrics::new_metric(
					        name_str.c_str(),
					        METRICS_V2_KERNEL_COUNTERS_PER_CPU,
					        METRIC_VALUE_TYPE_U64,
					        METRIC_VALUE_UNIT_COUNT,
					        METRIC_VALUE_METRIC_TYPE_MONOTONIC,
					        metric.value.u64);
					const std::map<std::string, std::string>& const_labels = {{"cpu", cpu_number}};
					/* Examples ...
					    # HELP falcosecurity_scap_n_evts_cpu_total https://falco.org/docs/metrics/
					    # TYPE falcosecurity_scap_n_evts_cpu_total counter
					    falcosecurity_scap_n_evts_cpu_total{cpu="7"} 237
					    # HELP falcosecurity_scap_n_drops_cpu_total https://falco.org/docs/metrics/
					    # TYPE falcosecurity_scap_n_drops_cpu_total counter
					    falcosecurity_scap_n_drops_cpu_total{cpu="7"} 0
					*/
					prometheus_text +=
					        prometheus_metrics_converter.convert_metric_to_text_prometheus(
					                metric_new,
					                "falcosecurity",
					                prometheus_subsystem,
					                const_labels);
				}
			} else if(strcmp(metric.name, "n_drops_buffer_total") == 0) {
				// Skip the libs aggregate metric since we distinguish between buffer drops using
				// labels similar to the rules_matches
				continue;
			} else if(strncmp(metric.name, "n_drops_buffer", 14) == 0)  // prefix match
			{
				re2::RE2 pattern("n_drops_buffer_([^_]+(?:_[^_]+)*)_(enter|exit)$");
				std::string drop;
				std::string dir;
				std::string name_str(metric.name);
				if(re2::RE2::FullMatch(name_str, pattern, &drop, &dir)) {
					auto metric_new = libs::metrics::libsinsp_metrics::new_metric(
					        "n_drops_buffer",
					        METRICS_V2_KERNEL_COUNTERS,
					        METRIC_VALUE_TYPE_U64,
					        METRIC_VALUE_UNIT_COUNT,
					        METRIC_VALUE_METRIC_TYPE_MONOTONIC,
					        metric.value.u64);
					const std::map<std::string, std::string>& const_labels = {{"drop", drop},
					                                                          {"dir", dir}};
					/* Examples ...
					    # HELP falcosecurity_scap_n_drops_buffer_total
					   https://falco.org/docs/metrics/ # TYPE
					   falcosecurity_scap_n_drops_buffer_total counter
					    falcosecurity_scap_n_drops_buffer_total{dir="enter",drop="clone_fork"} 0
					    # HELP falcosecurity_scap_n_drops_buffer_total
					   https://falco.org/docs/metrics/ # TYPE
					   falcosecurity_scap_n_drops_buffer_total counter
					    falcosecurity_scap_n_drops_buffer_total{dir="exit",drop="clone_fork"} 0
					*/
					prometheus_text +=
					        prometheus_metrics_converter.convert_metric_to_text_prometheus(
					                metric_new,
					                "falcosecurity",
					                prometheus_subsystem,
					                const_labels);
				}
			} else {
				prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
				        metric,
				        "falcosecurity",
				        prometheus_subsystem);
			}
		}
	}
	return prometheus_text;
}
