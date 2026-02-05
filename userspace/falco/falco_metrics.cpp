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
    \brief Converts metrics provided by the application and Falco libraries into a formatted string
           for the metrics endpoint.

    ## Metrics Overview
    This section explains why looping over inspectors is necessary.
    Falco utilizes multiple inspectors when loading plugins with an event source.
    Most metrics should only be retrieved once, ideally by the syscalls inspector if applicable.
    To maximize metrics retrieval and prevent duplicate data, the syscalls inspector is always
    positioned at index 0 in the loop when it exists.

    Wrapper fields: See https://falco.org/docs/concepts/metrics/
    - `engine_name` and `event_source` are pushed for each inspector.
    - All other wrapper fields are agnostic and should be retrieved once.

    ## Metrics Collection Behavior
    - `rules_counters_enabled` -> Agnostic; resides in falco; retrieved from the state, not an
      inspector; only performed once.
    - `resource_utilization_enabled` -> Agnostic; resides in libs; inspector is irrelevant;
      only performed once.
    - `state_counters_enabled` -> Semi-agnostic; resides in libs; must be retrieved by the syscalls
      inspector if applicable.
    - `kernel_event_counters_enabled` -> Resides in libs; must be retrieved by the syscalls
   inspector; not available for other inspectors.
    - `kernel_event_counters_per_cpu_enabled` -> Resides in libs; must be retrieved by the syscalls
      inspector; not available for other inspectors.
    - `libbpf_stats_enabled` -> Resides in libs; must be retrieved by the syscalls inspector;
      not available for other inspectors.
    - `plugins_metrics_enabled` -> Must be retrieved for each inspector.
    - `jemalloc_stats_enabled` -> Agnostic; resides in falco; inspector is irrelevant;
      only performed once.
*/

/*!
    \brief content_type to be returned by the webserver's metrics endpoint.

    Currently it is the default Prometheus exposition format

    https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format
*/
const std::string falco_metrics::content_type_prometheus = "text/plain; version=0.0.4";

// Helper function to convert metric to prometheus text with custom help text
static std::string convert_metric_to_text_prometheus_with_deprecation_notice(
        libs::metrics::prometheus_metrics_converter& converter,
        const metrics_v2& metric,
        const std::string& prefix,
        const std::string& subsystem,
        const std::map<std::string, std::string>& labels) {
	// First get the standard prometheus text
	std::string prometheus_text =
	        converter.convert_metric_to_text_prometheus(metric, prefix, subsystem, labels);

	// Find the first occurrence of "# HELP" and append the deprecation notice
	size_t help_pos = prometheus_text.find("# HELP");
	if(help_pos != std::string::npos) {
		// Find the end of the help line
		size_t help_end = prometheus_text.find('\n', help_pos);
		if(help_end != std::string::npos) {
			// Append (DEPRECATED: enter events are no longer tracked in falcosecurity/libs) to the
			// help text
			prometheus_text.insert(
			        help_end,
			        " (DEPRECATED: enter events are no longer tracked in falcosecurity/libs)");
		}
	}

	return prometheus_text;
}

std::string falco_metrics::falco_to_text_prometheus(
        const falco::app::state& state,
        libs::metrics::prometheus_metrics_converter& prometheus_metrics_converter,
        std::vector<metrics_v2>& additional_wrapper_metrics) {
	std::string prometheus_text;

	// # HELP falcosecurity_falco_version_info https://falco.org/docs/metrics/
	// # TYPE falcosecurity_falco_version_info gauge
	// falcosecurity_falco_version_info{version="0.41.0-100+334ca42"} 1
	prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
	        "version",
	        "falcosecurity",
	        "falco",
	        {{"version", FALCO_VERSION}});

#if defined(__linux__) and !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
	// Note that the rule counter metrics are retrieved from the state, not from any inspector
	// Distinguish between config and rules files using labels, following Prometheus best
	// practices: https://prometheus.io/docs/practices/naming/#labels

	// # HELP falcosecurity_falco_sha256_rules_files_info https://falco.org/docs/metrics/
	// # TYPE falcosecurity_falco_sha256_rules_files_info gauge
	// falcosecurity_falco_sha256_rules_files_info{file_name="falco_rules.yaml",sha256="6f0078862a26528cb50a860f9ebebbfbe3162e5009187089c73cb0cdf91d0b06"}
	// 1
	for(const auto& item : state.config.get()->m_loaded_rules_filenames_sha256sum) {
		fs::path fs_path = item.first;
		prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
		        "sha256_rules_files",
		        "falcosecurity",
		        "falco",
		        {{"file_name", fs_path.filename()}, {"sha256", item.second}});
	}

	// # HELP falcosecurity_falco_sha256_config_files_info https://falco.org/docs/metrics/
	// # TYPE falcosecurity_falco_sha256_config_files_info gauge
	// falcosecurity_falco_sha256_config_files_info{file_name="falco.yaml",sha256="f97de5fa6f513b5e07cd9f29ee9904ee4267cb120ef6501f8555543d5a98dd1c"}
	// 1
	for(const auto& item : state.config.get()->m_loaded_configs_filenames_sha256sum) {
		fs::path fs_path = item.first;
		prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
		        "sha256_config_files",
		        "falcosecurity",
		        "falco",
		        {{"file_name", fs_path.filename()}, {"sha256", item.second}});
	}

#endif
	// # HELP falcosecurity_falco_outputs_queue_num_drops_total https://falco.org/docs/metrics/
	// # TYPE falcosecurity_falco_outputs_queue_num_drops_total counter
	// falcosecurity_falco_outputs_queue_num_drops_total 0
	if(state.outputs != nullptr) {
		additional_wrapper_metrics.emplace_back(libs::metrics::libsinsp_metrics::new_metric(
		        "outputs_queue_num_drops",
		        METRICS_V2_MISC,
		        METRIC_VALUE_TYPE_U64,
		        METRIC_VALUE_UNIT_COUNT,
		        METRIC_VALUE_METRIC_TYPE_MONOTONIC,
		        state.outputs->get_outputs_queue_num_drops()));
	}

	// # HELP falcosecurity_falco_reload_timestamp_nanoseconds https://falco.org/docs/metrics/
	// # TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge
	// falcosecurity_falco_reload_timestamp_nanoseconds 1748338536592811359
	additional_wrapper_metrics.emplace_back(libs::metrics::libsinsp_metrics::new_metric(
	        "reload_ts",
	        METRICS_V2_MISC,
	        METRIC_VALUE_TYPE_S64,
	        METRIC_VALUE_UNIT_TIME_TIMESTAMP_NS,
	        METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	        state.config->m_falco_reload_ts));

	if(state.config->m_metrics_flags & METRICS_V2_RULE_COUNTERS) {
		// rules_counters_enabled
		const stats_manager& rule_stats_manager = state.engine->get_rule_stats_manager();
		const indexed_vector<falco_rule>& rules = state.engine->get_rules();
		const std::vector<std::unique_ptr<std::atomic<uint64_t>>>& rules_by_id =
		        rule_stats_manager.get_by_rule_id();
		// Distinguish between rules counters using labels, following Prometheus best
		// practices: https://prometheus.io/docs/practices/naming/#labels
		for(size_t i = 0; i < rules_by_id.size(); i++) {
			auto rule = rules.at(i);
			auto count = rules_by_id[i]->load();
			if(count > 0) {
				// # HELP falcosecurity_falco_rules_matches_total https://falco.org/docs/metrics/
				// # TYPE falcosecurity_falco_rules_matches_total counter
				// falcosecurity_falco_rules_matches_total{priority="4",rule_name="Read sensitive
				// file
				// untrusted",source="syscall",tag_T1555="true",tag_container="true",tag_filesystem="true",tag_host="true",tag_maturity_stable="true",tag_mitre_credential_access="true"}
				// 32 # HELP falcosecurity_falco_rules_matches_total https://falco.org/docs/metrics/
				// # TYPE falcosecurity_falco_rules_matches_total counter
				// falcosecurity_falco_rules_matches_total{priority="5",rule_name="Terminal shell in
				// container",source="syscall",tag_T1059="true",tag_container="true",tag_maturity_stable="true",tag_mitre_execution="true",tag_shell="true"}
				// 1
				auto metric = libs::metrics::libsinsp_metrics::new_metric(
				        "rules_matches",
				        METRICS_V2_RULE_COUNTERS,
				        METRIC_VALUE_TYPE_U64,
				        METRIC_VALUE_UNIT_COUNT,
				        METRIC_VALUE_METRIC_TYPE_MONOTONIC,
				        count);
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
				prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
				        metric,
				        "falcosecurity",
				        "falco",
				        const_labels);
			}
		}
	}
#ifdef HAS_JEMALLOC
	if(state.config->m_metrics_flags & METRICS_V2_JEMALLOC_STATS) {
		// jemalloc_stats_enabled
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
				prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
				        metric,
				        "falcosecurity",
				        "falco");
			}
		}
	}
#endif
	return prometheus_text;
}

std::string falco_metrics::sources_to_text_prometheus(
        const falco::app::state& state,
        libs::metrics::prometheus_metrics_converter& prometheus_metrics_converter,
        std::vector<metrics_v2>& additional_wrapper_metrics) {
	static const char* all_driver_engines[] = {KMOD_ENGINE,
	                                           MODERN_BPF_ENGINE,
	                                           SOURCE_PLUGIN_ENGINE,
	                                           NODRIVER_ENGINE};
	static re2::RE2 drops_buffer_pattern("n_drops_buffer_([^_]+(?:_[^_]+)*)_exit$");
	static re2::RE2 cpu_pattern("(\\d+)");

	std::string prometheus_text;
	bool agent_info_written = false;
	bool machine_info_written = false;

	// Then, source-bound metrics
	for(const auto& source : state.enabled_sources) {
		auto source_info = state.source_infos.at(source);
		auto source_inspector = source_info->inspector;

		// First thing: list of enabled engine names

		// Falco wrapper metrics Part A: Repeated for each inspector, accounting for plugins w/
		// event sources

		/* Examples ...
		    # HELP falcosecurity_scap_engine_name_info https://falco.org/docs/metrics/
		    # TYPE falcosecurity_scap_engine_name_info gauge
		    falcosecurity_scap_engine_name_info{engine_name="source_plugin",evt_source="dummy"} 1
		    # HELP falcosecurity_scap_engine_name_info https://falco.org/docs/metrics/
		    # TYPE falcosecurity_scap_engine_name_info gauge
		    falcosecurity_scap_engine_name_info{engine_name="bpf",evt_source="syscall"} 1
		*/

		for(size_t j = 0; j < sizeof(all_driver_engines) / sizeof(const char*); j++) {
			if(source_inspector->check_current_engine(all_driver_engines[j])) {
				prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
				        "engine_name",
				        "falcosecurity",
				        "scap",
				        {{"engine_name", std::string(all_driver_engines[j])},
				         {"evt_source", source}});
				break;
			}
		}

		// Inspectors' metrics collectors
		// Libs metrics categories
		//
		// resource_utilization_enabled
		// state_counters_enabled
		// kernel_event_counters_enabled
		// kernel_event_counters_per_cpu_enabled
		// libbpf_stats_enabled
		auto metrics_collector =
		        libs::metrics::libs_metrics_collector(source_inspector.get(),
		                                              state.config->m_metrics_flags);
		metrics_collector.snapshot();
		auto metrics_snapshot = metrics_collector.get_metrics();

		// Source plugin
		if(source != falco_common::syscall_source) {
			// Performed repeatedly for each inspectors' libs metrics collector
			for(auto& metric : metrics_snapshot) {
				if(metric.flags & METRICS_V2_PLUGINS) {
					prometheus_metrics_converter.convert_metric_to_unit_convention(metric);
					prometheus_text +=
					        prometheus_metrics_converter.convert_metric_to_text_prometheus(
					                metric,
					                "falcosecurity",
					                "plugins");
				}
			}
		} else {
			// Source syscall
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
					std::string cpu_number;
					if(re2::RE2::PartialMatch(name_str, cpu_pattern, &cpu_number)) {
						re2::RE2::GlobalReplace(&name_str, cpu_pattern, "");
						// possible double __ will be sanitized within libs
						auto metric_new = libs::metrics::libsinsp_metrics::new_metric(
						        name_str.c_str(),
						        METRICS_V2_KERNEL_COUNTERS_PER_CPU,
						        METRIC_VALUE_TYPE_U64,
						        METRIC_VALUE_UNIT_COUNT,
						        METRIC_VALUE_METRIC_TYPE_MONOTONIC,
						        metric.value.u64);
						const std::map<std::string, std::string>& const_labels = {
						        {"cpu", cpu_number}};
						/* Examples ...
						    # HELP falcosecurity_scap_n_evts_cpu_total
						   https://falco.org/docs/metrics/ # TYPE
						   falcosecurity_scap_n_evts_cpu_total counter
						    falcosecurity_scap_n_evts_cpu_total{cpu="7"} 237
						    # HELP falcosecurity_scap_n_drops_cpu_total
						   https://falco.org/docs/metrics/ # TYPE
						   falcosecurity_scap_n_drops_cpu_total counter
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
					// Skip the libs aggregate metric since we distinguish between buffer drops
					// using labels similar to the rules_matches
					continue;
				} else if(strncmp(metric.name, "n_drops_buffer", 14) == 0)  // prefix match
				{
					std::string drop;
					std::string name_str(metric.name);
					if(re2::RE2::FullMatch(name_str, drops_buffer_pattern, &drop)) {
						auto metric_new = libs::metrics::libsinsp_metrics::new_metric(
						        "n_drops_buffer",
						        METRICS_V2_KERNEL_COUNTERS,
						        METRIC_VALUE_TYPE_U64,
						        METRIC_VALUE_UNIT_COUNT,
						        METRIC_VALUE_METRIC_TYPE_MONOTONIC,
						        metric.value.u64);
						const std::map<std::string, std::string>& const_labels = {{"drop", drop},
						                                                          {"dir", "exit"}};
						/* Examples ...
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
					prometheus_text +=
					        prometheus_metrics_converter.convert_metric_to_text_prometheus(
					                metric,
					                "falcosecurity",
					                prometheus_subsystem);
				}
			}

			// Add deprecated enter event metrics with 0 values for backward compatibility
			static const std::vector<std::string> deprecated_enter_drops =
			        {"clone_fork", "execve", "connect", "open", "dir_file", "other_interest"};

			for(const auto& drop_type : deprecated_enter_drops) {
				auto metric_new = libs::metrics::libsinsp_metrics::new_metric(
				        "n_drops_buffer",
				        METRICS_V2_KERNEL_COUNTERS,
				        METRIC_VALUE_TYPE_U64,
				        METRIC_VALUE_UNIT_COUNT,
				        METRIC_VALUE_METRIC_TYPE_MONOTONIC,
				        0);  // Always 0 for deprecated enter events
				const std::map<std::string, std::string>& const_labels = {{"drop", drop_type},
				                                                          {"dir", "enter"}};

				// Add deprecation notice to the help text
				prometheus_text += convert_metric_to_text_prometheus_with_deprecation_notice(
				        prometheus_metrics_converter,
				        metric_new,
				        "falcosecurity",
				        "scap",  // Use "scap" subsystem for kernel counters
				        const_labels);
			}
		}

		// Source wrapper metrics Part B: Agnostic, performed only once.
		if(agent_info_written && machine_info_written) {
			continue;
		}

		const scap_agent_info* agent_info = nullptr;
		if(!agent_info_written) {
			agent_info = source_inspector->get_agent_info();
		}
		const scap_machine_info* machine_info = nullptr;
		if(!machine_info_written) {
			machine_info = source_inspector->get_machine_info();
		}

		// Not all scap engines report agent and machine infos.
		// However, recent lib refactors enable a linux lite platform, allowing non-syscall
		// inspectors to retrieve these metrics if the syscall inspector is unavailable.
		// We only push these info once.
		if(agent_info) {
			prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
			        "kernel_release",
			        "falcosecurity",
			        "falco",
			        {{"kernel_release", agent_info->uname_r}});
			additional_wrapper_metrics.emplace_back(libs::metrics::libsinsp_metrics::new_metric(
			        "start_ts",
			        METRICS_V2_MISC,
			        METRIC_VALUE_TYPE_U64,
			        METRIC_VALUE_UNIT_TIME_TIMESTAMP_NS,
			        METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
			        agent_info->start_ts_epoch));
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
			agent_info_written = true;
		}

		if(machine_info) {
			prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(
			        "hostname",
			        "falcosecurity",
			        "evt",
			        {{"hostname", machine_info->hostname}});
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
			machine_info_written = true;
		}
	}  // End inspector loop

	return prometheus_text;
}

/*!
    \brief this method takes an application \c state and returns a textual representation of
    its configured metrics.

    The current implementation returns a Prometheus exposition formatted string.
*/
std::string falco_metrics::to_text_prometheus(const falco::app::state& state) {
	libs::metrics::prometheus_metrics_converter prometheus_metrics_converter;
	std::string prometheus_text;

	std::vector<metrics_v2> additional_wrapper_metrics;

	// Falco global metrics, once
	prometheus_text += falco_to_text_prometheus(state,
	                                            prometheus_metrics_converter,
	                                            additional_wrapper_metrics);
	// Metrics for each source
	prometheus_text += sources_to_text_prometheus(state,
	                                              prometheus_metrics_converter,
	                                              additional_wrapper_metrics);

	for(auto metric : additional_wrapper_metrics) {
		prometheus_metrics_converter.convert_metric_to_unit_convention(metric);
		prometheus_text +=
		        prometheus_metrics_converter.convert_metric_to_text_prometheus(metric,
		                                                                       "falcosecurity",
		                                                                       "falco");
	}

	return prometheus_text;
}
