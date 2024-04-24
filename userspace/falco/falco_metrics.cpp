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

#include "falco_metrics.h"

#include "app/state.h"

#include <libsinsp/sinsp.h>

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
std::string falco_metrics::to_text(const falco::app::state& state)
{
	static const char* all_driver_engines[] = {
		BPF_ENGINE, KMOD_ENGINE, MODERN_BPF_ENGINE,
		SOURCE_PLUGIN_ENGINE, NODRIVER_ENGINE, GVISOR_ENGINE };

	std::vector<sinsp*> inspectors;
	std::vector<libs::metrics::libs_metrics_collector> metrics_collectors;

	for (const auto& source_info: state.source_infos)
	{
		sinsp *source_inspector = source_info.inspector.get();
		inspectors.push_back(source_inspector);
		metrics_collectors.push_back(libs::metrics::libs_metrics_collector(source_inspector, state.config->m_metrics_flags));
	}

	libs::metrics::prometheus_metrics_converter prometheus_metrics_converter;
	std::string prometheus_text;

	for (auto* inspector: inspectors)
	{
		for (size_t i = 0; i < sizeof(all_driver_engines) / sizeof(const char*); i++)
		{
			if (inspector->check_current_engine(all_driver_engines[i]))
			{
				prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus("engine_name", "falcosecurity", "scap", {{"engine_name", all_driver_engines[i]}});
				break;
			}
		}

		const scap_agent_info* agent_info = inspector->get_agent_info();
		const scap_machine_info* machine_info = inspector->get_machine_info();

		libs::metrics::libs_metrics_collector libs_metrics_collector(inspector, 0);

		prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus("falco_version", "falcosecurity", "falco", {{"version", FALCO_VERSION}});
		prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus("kernel_release", "falcosecurity", "falco", {{"kernel_release", agent_info->uname_r}});
		prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus("hostname", "falcosecurity", "evt", {{"hostname", machine_info->hostname}});

		for (const std::string& source: inspector->event_sources())
		{
			prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus("evt_source", "falcosecurity", "falco", {{"evt_source", source}});
		}
		std::vector<metrics_v2> static_metrics;
		static_metrics.push_back(libs_metrics_collector.new_metric("start_ts",
																	METRICS_V2_MISC,
																	METRIC_VALUE_TYPE_U64,
																	METRIC_VALUE_UNIT_TIME_TIMESTAMP_NS,
																	METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
																	agent_info->start_ts_epoch));
		static_metrics.push_back(libs_metrics_collector.new_metric("host_boot_ts",
																	METRICS_V2_MISC,
																	METRIC_VALUE_TYPE_U64,
																	METRIC_VALUE_UNIT_TIME_TIMESTAMP_NS,
																	METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
																	machine_info->boot_ts_epoch));
		static_metrics.push_back(libs_metrics_collector.new_metric("host_num_cpus",
																	METRICS_V2_MISC,
																	METRIC_VALUE_TYPE_U32,
																	METRIC_VALUE_UNIT_COUNT,
																	METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
																	machine_info->num_cpus));
		static_metrics.push_back(libs_metrics_collector.new_metric("outputs_queue_num_drops",
																	METRICS_V2_MISC,
																	METRIC_VALUE_TYPE_U64,
																	METRIC_VALUE_UNIT_COUNT,
																	METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
																	state.outputs->get_outputs_queue_num_drops()));

		auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

		static_metrics.push_back(libs_metrics_collector.new_metric("duration_sec",
																	METRICS_V2_MISC,
																	METRIC_VALUE_TYPE_U64,
																	METRIC_VALUE_UNIT_TIME_TIMESTAMP_NS,
																	METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
																	(uint64_t)((now - agent_info->start_ts_epoch) / ONE_SECOND_IN_NS)));

		for (auto metrics: static_metrics)
		{
			prometheus_metrics_converter.convert_metric_to_unit_convention(metrics);
			prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(metrics, "falcosecurity", "falco");
		}
	}

	for (auto metrics_collector: metrics_collectors)
	{
		metrics_collector.snapshot();
		auto metrics_snapshot = metrics_collector.get_metrics();

		for (auto& metrics: metrics_snapshot)
		{
			prometheus_metrics_converter.convert_metric_to_unit_convention(metrics);
			std::string namespace_name = "scap";
			if (metrics.flags & METRICS_V2_RESOURCE_UTILIZATION || metrics.flags & METRICS_V2_KERNEL_COUNTERS)
			{
				namespace_name = "falco";
			}
			prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(metrics, "falcosecurity", namespace_name);
		}

	}
	return prometheus_text;
}
