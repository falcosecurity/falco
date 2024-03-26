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

falco_metrics::falco_metrics(falco::app::state& state)
{
	falco_configuration::webserver_config webserver_config = state.config->m_webserver_config;
	m_metrics_enabled = state.config->m_metrics_enabled && webserver_config.m_metrics_enabled;

	if (m_metrics_enabled)
	{
		for (const auto& source_info: state.source_infos)
		{
			sinsp *source_inspector = source_info.inspector.get();
			m_inspectors.push_back(source_inspector);
			m_metrics_collectors.push_back(libs::metrics::libs_metrics_collector(source_inspector, state.config->m_metrics_flags));	
		}
	}
}

std::string falco_metrics::to_text() const
{
	if (!m_metrics_enabled)
	{
		return "";
	}

	static const char* all_driver_engines[] = {
		BPF_ENGINE, KMOD_ENGINE, MODERN_BPF_ENGINE,
		SOURCE_PLUGIN_ENGINE, NODRIVER_ENGINE, GVISOR_ENGINE };


	libs::metrics::prometheus_metrics_converter prometheus_metrics_converter;
	std::string prometheus_text;

	for (auto* inspector: m_inspectors)
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

		prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus("falco_version", "falcosecurity", "falco", {{"falco_version", FALCO_VERSION}});
		prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus("kernel_release", "falcosecurity", "falco", {{"kernel_release", agent_info->uname_r}});
		prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus("evt_hostname", "falcosecurity", "falco", {{"evt_hostname", machine_info->hostname}});

		std::vector<metrics_v2> static_metrics;
		static_metrics.push_back(libs_metrics_collector.new_metric("start_ts",
											METRICS_V2_LIBBPF_STATS,
											METRIC_VALUE_TYPE_U64,
											METRIC_VALUE_UNIT_TIME_NS_COUNT,
											METRIC_VALUE_METRIC_TYPE_MONOTONIC,
											agent_info->start_ts_epoch));
		static_metrics.push_back(libs_metrics_collector.new_metric("falco_host_boot_ts",
											METRICS_V2_LIBBPF_STATS,
											METRIC_VALUE_TYPE_U64,
											METRIC_VALUE_UNIT_TIME_NS_COUNT,
											METRIC_VALUE_METRIC_TYPE_MONOTONIC,
											machine_info->boot_ts_epoch));
		static_metrics.push_back(libs_metrics_collector.new_metric("falco_host_num_cpus",
											METRICS_V2_LIBBPF_STATS,
											METRIC_VALUE_TYPE_U64,
											METRIC_VALUE_UNIT_TIME_NS_COUNT,
											METRIC_VALUE_METRIC_TYPE_MONOTONIC,
											machine_info->num_cpus));

		for (auto metrics: static_metrics)
		{
			prometheus_metrics_converter.convert_metric_to_unit_convention(metrics);
			prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(metrics, "falcosecurity", "falco");
		}
	}

	for (auto metrics_collector: m_metrics_collectors)
	{
		metrics_collector.snapshot();
		auto metrics_snapshot = metrics_collector.get_metrics();

		for (auto& metric: metrics_snapshot)
		{
		   prometheus_metrics_converter.convert_metric_to_unit_convention(metric);
		   prometheus_text += prometheus_metrics_converter.convert_metric_to_text_prometheus(metric, "falcosecurity", "scap");
		}
	}
	return prometheus_text;
}
