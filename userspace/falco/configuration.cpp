// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#include <algorithm>

#include <list>
#include <set>
#include <string>
#include <unordered_set>

#include <filesystem>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include "falco_utils.h"

#include "configuration.h"
#include "logger.h"

#include "config_json_schema.h"

#include <re2/re2.h>

namespace fs = std::filesystem;

// Reference: https://digitalfortress.tech/tips/top-15-commonly-used-regex/
static re2::RE2 ip_address_re(
        "((^\\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{"
        "2}|2[0-4][0-9]|25[0-5]))\\s*$)|(^\\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-"
        "9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2["
        "0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:(("
        "25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|((["
        "0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\\d|"
        "1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:)"
        "{3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]"
        "?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-"
        "Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25["
        "0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){"
        "1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]"
        "\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:("
        "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:)))("
        "%.+)?\\s*$))");

#define DEFAULT_BUF_SIZE_PRESET 4
#define DEFAULT_CPUS_FOR_EACH_SYSCALL_BUFFER 2
#define DEFAULT_DROP_FAILED_EXIT false

falco_configuration::falco_configuration():
        m_json_output(false),
        m_json_include_output_property(true),
        m_json_include_tags_property(true),
        m_json_include_message_property(false),
        m_json_include_output_fields_property(true),
        m_rule_matching(falco_common::rule_matching::FIRST),
        m_watch_config_files(true),
        m_buffered_outputs(false),
        m_outputs_queue_capacity(DEFAULT_OUTPUTS_QUEUE_CAPACITY_UNBOUNDED_MAX_LONG_VALUE),
        m_time_format_iso_8601(false),
        m_buffer_format_base64(false),
        m_output_timeout(2000),
        m_webserver_enabled(false),
        m_syscall_evt_drop_threshold(.1),
        m_syscall_evt_drop_rate(.03333),
        m_syscall_evt_drop_max_burst(1),
        m_syscall_evt_simulate_drops(false),
        m_syscall_evt_timeout_max_consecutives(1000),
        m_falco_libs_thread_table_size(DEFAULT_FALCO_LIBS_THREAD_TABLE_SIZE),
        m_falco_libs_thread_table_auto_purging_interval_s(
                DEFAULT_FALCO_LIBS_THREAD_TABLE_AUTO_PURGING_INTERVAL_S),
        m_falco_libs_thread_table_auto_purging_thread_timeout_s(
                DEFAULT_FALCO_LIBS_THREAD_TABLE_AUTO_PURGING_THREAD_TIMEOUT_S),
        m_falco_libs_snaplen(0),
        m_base_syscalls_all(false),
        m_base_syscalls_repair(false),
        m_metrics_enabled(false),
        m_metrics_interval_str("5000"),
        m_metrics_interval(5000),
        m_metrics_stats_rule_enabled(false),
        m_metrics_output_file(""),
        m_metrics_flags(0),
        m_metrics_convert_memory_to_mb(true),
        m_metrics_include_empty_values(false),
        m_plugins_hostinfo(true),
        m_capture_enabled(false),
        m_capture_path_prefix("/tmp/falco"),
        m_capture_mode(capture_mode_t::RULES),
        m_capture_default_duration_ns(5000 * 1000000LL) {
	m_config_schema = nlohmann::json::parse(config_schema_string);
}

config_loaded_res falco_configuration::init_from_content(
        const std::string &config_content,
        const std::vector<std::string> &cmdline_options,
        const std::string &filename) {
	config_loaded_res res;
	std::vector<std::string> validation_status;

	m_config.load_from_string(config_content, m_config_schema, &validation_status);
	init_cmdline_options(cmdline_options);

	// Only report top most schema validation status
	res[filename] = validation_status[0];

	load_yaml(filename);
	return res;
}

config_loaded_res falco_configuration::init_from_file(
        const std::string &conf_filename,
        const std::vector<std::string> &cmdline_options) {
	config_loaded_res res;
	std::vector<std::string> validation_status;
	try {
		m_config.load_from_file(conf_filename, m_config_schema, &validation_status);
	} catch(const std::exception &e) {
		std::cerr << "Cannot read config file (" + conf_filename + "): " + e.what() + "\n";
		throw e;
	}

	// Only report top most schema validation status
	res[conf_filename] = validation_status[0];

	// Load any `-o config_files=foo.yaml` cmdline additional option
	load_cmdline_config_files(cmdline_options);

	// Merge all config files (both from main falco.yaml and `-o config_files=foo.yaml`)
	merge_config_files(conf_filename, res);

	// Load all other `-o` cmdline options to override any config key
	init_cmdline_options(cmdline_options);

	// Finally load the parsed config to our structure
	load_yaml(conf_filename);

	return res;
}

std::string falco_configuration::dump() {
	return m_config.dump();
}

// Load configs files to be included and merge them into current config
// NOTE: loaded_config_files will resolve to the filepaths list of loaded config.
// m_loaded_configs_filenames and m_loaded_configs_folders instead will hold the list of
// filenames and folders specified in config (minus the skipped ones).
void falco_configuration::merge_config_files(const std::string &config_name,
                                             config_loaded_res &res) {
	std::vector<std::string> validation_status;
	m_loaded_configs_filenames.push_back(config_name);
	const auto ppath = std::filesystem::path(config_name);
	// Parse files to be included
	std::list<falco_configuration::config_files_config> include_files;
	m_config.get_sequence<std::list<falco_configuration::config_files_config>>(
	        include_files,
	        yaml_helper::configs_key);
	for(const auto &include_file : include_files) {
		auto include_file_path = std::filesystem::path(include_file.m_path);
		if(include_file_path == ppath) {
			throw std::logic_error("Config error: '" + yaml_helper::configs_key +
			                       "' directive tried to recursively include main config file: " +
			                       config_name + ".");
		}
		if(!std::filesystem::exists(include_file_path)) {
			// Same we do for rules_file: just skip the entry.
			continue;
		}
		if(std::filesystem::is_regular_file(include_file_path)) {
			m_loaded_configs_filenames.push_back(include_file.m_path);
			m_config.include_config_file(include_file.m_path,
			                             include_file.m_strategy,
			                             m_config_schema,
			                             &validation_status);
			// Only report top most schema validation status
			res[include_file.m_path] = validation_status[0];
		} else if(std::filesystem::is_directory(include_file_path)) {
			m_loaded_configs_folders.push_back(include_file.m_path);
			std::vector<std::string> v;
			const auto it_options = std::filesystem::directory_options::follow_directory_symlink |
			                        std::filesystem::directory_options::skip_permission_denied;
			for(auto const &dir_entry :
			    std::filesystem::directory_iterator(include_file_path, it_options)) {
				if(std::filesystem::is_regular_file(dir_entry.path())) {
					v.push_back(dir_entry.path().string());
				}
			}
			std::sort(v.begin(), v.end());
			for(const auto &f : v) {
				m_config.include_config_file(f,
				                             include_file.m_strategy,
				                             m_config_schema,
				                             &validation_status);
				// Only report top most schema validation status
				res[f] = validation_status[0];
			}
		}
	}

#if defined(__linux__) and !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
	for(auto &filename : m_loaded_configs_filenames) {
		m_loaded_configs_filenames_sha256sum.insert(
		        {filename, falco::utils::calculate_file_sha256sum(filename)});
	}
#endif
}

void falco_configuration::init_logger() {
	m_log_level = m_config.get_scalar<std::string>("log_level", "info");
	falco_logger::set_level(m_log_level);
	falco_logger::set_sinsp_logging(
	        m_config.get_scalar<bool>("libs_logger.enabled", true),
	        m_config.get_scalar<std::string>("libs_logger.severity", "info"),
	        "[libs]: ");
	falco_logger::log_stderr = m_config.get_scalar<bool>("log_stderr", false);
	falco_logger::log_syslog = m_config.get_scalar<bool>("log_syslog", true);
}

void falco_configuration::load_engine_config(const std::string &config_name) {
	// Set driver mode if not already set.
	const std::unordered_map<std::string, engine_kind_t> engine_mode_lut = {
	        {"kmod", engine_kind_t::KMOD},
	        {"modern_ebpf", engine_kind_t::MODERN_EBPF},
	        {"replay", engine_kind_t::REPLAY},
	        {"nodriver", engine_kind_t::NODRIVER},
	};

	auto driver_mode_str = m_config.get_scalar<std::string>("engine.kind", "kmod");
	if(engine_mode_lut.find(driver_mode_str) != engine_mode_lut.end()) {
		m_engine_mode = engine_mode_lut.at(driver_mode_str);
	} else {
		throw std::logic_error("Error reading config file (" + config_name + "): engine.kind '" +
		                       driver_mode_str + "' is not a valid kind.");
	}

	switch(m_engine_mode) {
	case engine_kind_t::KMOD:
		m_kmod.m_buf_size_preset = m_config.get_scalar<int16_t>("engine.kmod.buf_size_preset",
		                                                        DEFAULT_BUF_SIZE_PRESET);
		m_kmod.m_drop_failed_exit =
		        m_config.get_scalar<bool>("engine.kmod.drop_failed_exit", DEFAULT_DROP_FAILED_EXIT);
		break;
	case engine_kind_t::MODERN_EBPF:
		m_modern_ebpf.m_cpus_for_each_buffer =
		        m_config.get_scalar<uint16_t>("engine.modern_ebpf.cpus_for_each_buffer",
		                                      DEFAULT_CPUS_FOR_EACH_SYSCALL_BUFFER);
		m_modern_ebpf.m_buf_size_preset =
		        m_config.get_scalar<int16_t>("engine.modern_ebpf.buf_size_preset",
		                                     DEFAULT_BUF_SIZE_PRESET);
		m_modern_ebpf.m_drop_failed_exit =
		        m_config.get_scalar<bool>("engine.modern_ebpf.drop_failed_exit",
		                                  DEFAULT_DROP_FAILED_EXIT);
		break;
	case engine_kind_t::REPLAY:
		m_replay.m_capture_file =
		        m_config.get_scalar<std::string>("engine.replay.capture_file", "");
		if(m_replay.m_capture_file.empty()) {
			throw std::logic_error(
			        "Error reading config file (" + config_name +
			        "): engine.kind is 'replay' but no engine.replay.capture_file specified.");
		}
		break;
	case engine_kind_t::NODRIVER:
	default:
		break;
	}
}

void falco_configuration::load_yaml(const std::string &config_name) {
	init_logger();
	load_engine_config(config_name);

	std::list<std::string> rules_files;

	// Small glue code to support old deprecated 'rules_file' config key.
	int num_rules_files_opts = 0;
	if(m_config.is_defined("rules_files")) {
		num_rules_files_opts++;
		m_config.get_sequence<std::list<std::string>>(rules_files, std::string("rules_files"));
	}
	if(m_config.is_defined("rules_file")) {
		num_rules_files_opts++;
		m_config.get_sequence<std::list<std::string>>(rules_files, std::string("rules_file"));
		falco_logger::log(falco_logger::level::WARNING,
		                  "Using deprecated config key 'rules_file' (singular form). Please use "
		                  "new 'rules_files' config key (plural form).");
	}
	if(num_rules_files_opts == 2) {
		throw std::logic_error("Error reading config file (" + config_name +
		                       "): both 'rules_files' and 'rules_file' keys set");
	}

	m_rules_filenames.clear();
	m_loaded_rules_filenames.clear();
	m_loaded_rules_filenames_sha256sum.clear();
	m_loaded_rules_folders.clear();
	for(const auto &file : rules_files) {
		// Here, we only include files that exist
		struct stat buffer;
		if(stat(file.c_str(), &buffer) == 0) {
			m_rules_filenames.push_back(file);
		}
	}

	m_json_output = m_config.get_scalar<bool>("json_output", false);
	m_json_include_output_property =
	        m_config.get_scalar<bool>("json_include_output_property", true);
	m_json_include_tags_property = m_config.get_scalar<bool>("json_include_tags_property", true);
	m_json_include_message_property =
	        m_config.get_scalar<bool>("json_include_message_property", false);
	m_json_include_output_fields_property =
	        m_config.get_scalar<bool>("json_include_output_fields_property", true);

	m_outputs.clear();
	falco::outputs::config file_output;
	file_output.name = "file";
	if(m_config.get_scalar<bool>("file_output.enabled", false)) {
		std::string filename, keep_alive;
		filename = m_config.get_scalar<std::string>("file_output.filename", "");
		if(filename == std::string("")) {
			throw std::logic_error("Error reading config file (" + config_name +
			                       "): file output enabled but no filename in configuration block");
		}
		file_output.options["filename"] = filename;

		keep_alive = m_config.get_scalar<std::string>("file_output.keep_alive", "");
		file_output.options["keep_alive"] = keep_alive;

		m_outputs.push_back(file_output);
	}

	falco::outputs::config stdout_output;
	stdout_output.name = "stdout";
	if(m_config.get_scalar<bool>("stdout_output.enabled", false)) {
		m_outputs.push_back(stdout_output);
	}

	falco::outputs::config syslog_output;
	syslog_output.name = "syslog";
	if(m_config.get_scalar<bool>("syslog_output.enabled", false)) {
		m_outputs.push_back(syslog_output);
	}

	falco::outputs::config program_output;
	program_output.name = "program";
	if(m_config.get_scalar<bool>("program_output.enabled", false)) {
		std::string program, keep_alive;
		program = m_config.get_scalar<std::string>("program_output.program", "");
		if(program == std::string("")) {
			throw std::logic_error(
			        "Error reading config file (" + config_name +
			        "): program output enabled but no program in configuration block");
		}
		program_output.options["program"] = program;

		keep_alive = m_config.get_scalar<std::string>("program_output.keep_alive", "");
		program_output.options["keep_alive"] = keep_alive;

		m_outputs.push_back(program_output);
	}

	falco::outputs::config http_output;
	http_output.name = "http";
	if(m_config.get_scalar<bool>("http_output.enabled", false)) {
		std::string url;
		url = m_config.get_scalar<std::string>("http_output.url", "");

		if(url == std::string("")) {
			throw std::logic_error("Error reading config file (" + config_name +
			                       "): http output enabled but no url in configuration block");
		}
		http_output.options["url"] = url;

		std::string user_agent;
		user_agent =
		        m_config.get_scalar<std::string>("http_output.user_agent", "falcosecurity/falco");
		http_output.options["user_agent"] = user_agent;

		bool insecure;
		insecure = m_config.get_scalar<bool>("http_output.insecure", false);
		http_output.options["insecure"] = insecure ? std::string("true") : std::string("false");

		bool echo;
		echo = m_config.get_scalar<bool>("http_output.echo", false);
		http_output.options["echo"] = echo ? std::string("true") : std::string("false");

		std::string ca_cert;
		ca_cert = m_config.get_scalar<std::string>("http_output.ca_cert", "");
		http_output.options["ca_cert"] = ca_cert;

		std::string ca_bundle;
		ca_bundle = m_config.get_scalar<std::string>("http_output.ca_bundle", "");
		http_output.options["ca_bundle"] = ca_bundle;

		std::string ca_path;
		ca_path = m_config.get_scalar<std::string>("http_output.ca_path", "/etc/ssl/certs");
		http_output.options["ca_path"] = ca_path;

		bool mtls;
		mtls = m_config.get_scalar<bool>("http_output.mtls", false);
		http_output.options["mtls"] = mtls ? std::string("true") : std::string("false");

		std::string client_cert;
		client_cert = m_config.get_scalar<std::string>("http_output.client_cert",
		                                               "/etc/ssl/certs/client.crt");
		http_output.options["client_cert"] = client_cert;

		std::string client_key;
		client_key = m_config.get_scalar<std::string>("http_output.client_key",
		                                              "/etc/ssl/certs/client.key");
		http_output.options["client_key"] = client_key;

		bool compress_uploads;
		compress_uploads = m_config.get_scalar<bool>("http_output.compress_uploads", false);
		http_output.options["compress_uploads"] =
		        compress_uploads ? std::string("true") : std::string("false");

		bool keep_alive;
		keep_alive = m_config.get_scalar<bool>("http_output.keep_alive", false);
		http_output.options["keep_alive"] = keep_alive ? std::string("true") : std::string("false");

		uint8_t max_consecutive_timeouts;
		max_consecutive_timeouts =
		        m_config.get_scalar<uint8_t>("http_output.max_consecutive_timeouts", 5);
		http_output.options["max_consecutive_timeouts"] = std::to_string(max_consecutive_timeouts);

		m_outputs.push_back(http_output);
	}

	m_output_timeout = m_config.get_scalar<uint32_t>("output_timeout", 2000);

	std::string rule_matching = m_config.get_scalar<std::string>("rule_matching", "first");
	if(!falco_common::parse_rule_matching(rule_matching, m_rule_matching)) {
		throw std::logic_error("Unknown rule matching strategy \"" + rule_matching +
		                       "\"--must be one of first, all");
	}

	std::string priority = m_config.get_scalar<std::string>("priority", "debug");
	if(!falco_common::parse_priority(priority, m_min_priority)) {
		throw std::logic_error("Unknown priority \"" + priority +
		                       "\"--must be one of emergency, alert, critical, error, warning, "
		                       "notice, informational, debug");
	}

	m_buffered_outputs = m_config.get_scalar<bool>("buffered_outputs", false);
	m_outputs_queue_capacity =
	        m_config.get_scalar<size_t>("outputs_queue.capacity",
	                                    DEFAULT_OUTPUTS_QUEUE_CAPACITY_UNBOUNDED_MAX_LONG_VALUE);
	// We use 0 in falco.yaml to indicate an unbounded queue; equivalent to the largest long value
	if(m_outputs_queue_capacity == 0) {
		m_outputs_queue_capacity = DEFAULT_OUTPUTS_QUEUE_CAPACITY_UNBOUNDED_MAX_LONG_VALUE;
	}

	m_time_format_iso_8601 = m_config.get_scalar<bool>("time_format_iso_8601", false);
	m_buffer_format_base64 = m_config.get_scalar<bool>("buffer_format_base64", false);

	m_webserver_enabled = m_config.get_scalar<bool>("webserver.enabled", false);
	m_webserver_config.m_threadiness = m_config.get_scalar<uint32_t>("webserver.threadiness", 0);
	m_webserver_config.m_listen_port = m_config.get_scalar<uint32_t>("webserver.listen_port", 8765);
	m_webserver_config.m_listen_address =
	        m_config.get_scalar<std::string>("webserver.listen_address", "0.0.0.0");
	if(!re2::RE2::FullMatch(m_webserver_config.m_listen_address, ip_address_re)) {
		throw std::logic_error(
		        "Error reading config file (" + config_name + "): webserver listen address \"" +
		        m_webserver_config.m_listen_address + "\" is not a valid IP address");
	}

	m_webserver_config.m_k8s_healthz_endpoint =
	        m_config.get_scalar<std::string>("webserver.k8s_healthz_endpoint", "/healthz");
	m_webserver_config.m_ssl_enabled = m_config.get_scalar<bool>("webserver.ssl_enabled", false);
	m_webserver_config.m_ssl_certificate =
	        m_config.get_scalar<std::string>("webserver.ssl_certificate", "/etc/falco/falco.pem");
	if(m_webserver_config.m_threadiness == 0) {
		m_webserver_config.m_threadiness = falco::utils::hardware_concurrency();
	}
	m_webserver_config.m_prometheus_metrics_enabled =
	        m_config.get_scalar<bool>("webserver.prometheus_metrics_enabled", false);

	std::list<std::string> syscall_event_drop_acts;
	m_config.get_sequence(syscall_event_drop_acts, "syscall_event_drops.actions");

	m_syscall_evt_drop_actions.clear();
	for(const std::string &act : syscall_event_drop_acts) {
		if(act == "ignore") {
			m_syscall_evt_drop_actions.insert(syscall_evt_drop_action::DISREGARD);
		} else if(act == "log") {
			if(m_syscall_evt_drop_actions.count(syscall_evt_drop_action::DISREGARD)) {
				throw std::logic_error("Error reading config file (" + config_name +
				                       "): syscall event drop action \"" + act +
				                       "\" does not make sense with the \"ignore\" action");
			}
			m_syscall_evt_drop_actions.insert(syscall_evt_drop_action::LOG);
		} else if(act == "alert") {
			if(m_syscall_evt_drop_actions.count(syscall_evt_drop_action::DISREGARD)) {
				throw std::logic_error("Error reading config file (" + config_name +
				                       "): syscall event drop action \"" + act +
				                       "\" does not make sense with the \"ignore\" action");
			}
			m_syscall_evt_drop_actions.insert(syscall_evt_drop_action::ALERT);
		} else if(act == "exit") {
			m_syscall_evt_drop_actions.insert(syscall_evt_drop_action::EXIT);
		} else {
			throw std::logic_error("Error reading config file (" + config_name +
			                       "): available actions for syscall event drops are \"ignore\", "
			                       "\"log\", \"alert\", and \"exit\"");
		}
	}

	if(m_syscall_evt_drop_actions.empty()) {
		m_syscall_evt_drop_actions.insert(syscall_evt_drop_action::DISREGARD);
	}

	m_syscall_evt_drop_threshold = m_config.get_scalar<double>("syscall_event_drops.threshold", .1);
	if(m_syscall_evt_drop_threshold < 0 || m_syscall_evt_drop_threshold > 1) {
		throw std::logic_error(
		        "Error reading config file (" + config_name +
		        "): syscall event drops threshold must be a double in the range [0, 1]");
	}
	m_syscall_evt_drop_rate = m_config.get_scalar<double>("syscall_event_drops.rate", .03333);
	m_syscall_evt_drop_max_burst = m_config.get_scalar<double>("syscall_event_drops.max_burst", 1);
	m_syscall_evt_simulate_drops =
	        m_config.get_scalar<bool>("syscall_event_drops.simulate_drops", false);

	m_syscall_evt_timeout_max_consecutives =
	        m_config.get_scalar<uint32_t>("syscall_event_timeouts.max_consecutives", 1000);
	if(m_syscall_evt_timeout_max_consecutives == 0) {
		throw std::logic_error("Error reading config file(" + config_name +
		                       "): the maximum consecutive timeouts without an event must be an "
		                       "unsigned integer > 0");
	}

	m_falco_libs_thread_table_size =
	        m_config.get_scalar<std::uint32_t>("falco_libs.thread_table_size",
	                                           DEFAULT_FALCO_LIBS_THREAD_TABLE_SIZE);
	m_falco_libs_thread_table_auto_purging_interval_s = m_config.get_scalar<std::uint32_t>(
	        "falco_libs.thread_table_auto_purging_interval_s",
	        DEFAULT_FALCO_LIBS_THREAD_TABLE_AUTO_PURGING_INTERVAL_S);
	m_falco_libs_thread_table_auto_purging_thread_timeout_s = m_config.get_scalar<std::uint32_t>(
	        "falco_libs.thread_table_auto_purging_thread_timeout_s",
	        DEFAULT_FALCO_LIBS_THREAD_TABLE_AUTO_PURGING_THREAD_TIMEOUT_S);

	// if falco_libs.snaplen is not set we'll let libs configure it
	m_falco_libs_snaplen = m_config.get_scalar<std::uint64_t>("falco_libs.snaplen", 0);

	m_base_syscalls_custom_set.clear();
	m_config.get_sequence<std::unordered_set<std::string>>(m_base_syscalls_custom_set,
	                                                       std::string("base_syscalls.custom_set"));
	m_base_syscalls_repair = m_config.get_scalar<bool>("base_syscalls.repair", false);
	m_base_syscalls_all = m_config.get_scalar<bool>("base_syscalls.all", false);

	m_metrics_enabled = m_config.get_scalar<bool>("metrics.enabled", false);
	m_metrics_interval_str = m_config.get_scalar<std::string>("metrics.interval", "5000");
	m_metrics_interval = falco::utils::parse_prometheus_interval(m_metrics_interval_str);
	m_metrics_stats_rule_enabled = m_config.get_scalar<bool>("metrics.output_rule", false);
	m_metrics_output_file = m_config.get_scalar<std::string>("metrics.output_file", "");

	m_metrics_flags = 0;
	if(m_config.get_scalar<bool>("metrics.rules_counters_enabled", true)) {
		m_metrics_flags |= METRICS_V2_RULE_COUNTERS;
	}
	if(m_config.get_scalar<bool>("metrics.resource_utilization_enabled", true)) {
		m_metrics_flags |= METRICS_V2_RESOURCE_UTILIZATION;
	}
	if(m_config.get_scalar<bool>("metrics.state_counters_enabled", true)) {
		m_metrics_flags |= METRICS_V2_STATE_COUNTERS;
	}
	if(m_config.get_scalar<bool>("metrics.kernel_event_counters_enabled", true)) {
		m_metrics_flags |= METRICS_V2_KERNEL_COUNTERS;
	}
	if(m_config.get_scalar<bool>("metrics.kernel_event_counters_per_cpu_enabled", true)) {
		m_metrics_flags |= METRICS_V2_KERNEL_COUNTERS_PER_CPU;
	}
	if(m_config.get_scalar<bool>("metrics.libbpf_stats_enabled", true)) {
		m_metrics_flags |= METRICS_V2_LIBBPF_STATS;
	}
	if(m_config.get_scalar<bool>("metrics.plugins_metrics_enabled", true)) {
		m_metrics_flags |= METRICS_V2_PLUGINS;
	}
	if(m_config.get_scalar<bool>("metrics.jemalloc_stats_enabled", true)) {
		m_metrics_flags |= METRICS_V2_JEMALLOC_STATS;
	}

	m_metrics_convert_memory_to_mb =
	        m_config.get_scalar<bool>("metrics.convert_memory_to_mb", true);
	m_metrics_include_empty_values =
	        m_config.get_scalar<bool>("metrics.include_empty_values", false);

	m_capture_enabled = m_config.get_scalar<bool>("capture.enabled", false);
	m_capture_path_prefix = m_config.get_scalar<std::string>("capture.path_prefix", "/tmp/falco");
	// Set capture mode if not already set.
	const std::unordered_map<std::string, capture_mode_t> capture_mode_lut = {
	        {"rules", capture_mode_t::RULES},
	        {"all_rules", capture_mode_t::ALL_RULES},
	};

	auto capture_mode_str = m_config.get_scalar<std::string>("capture.mode", "rules");
	if(capture_mode_lut.find(capture_mode_str) != capture_mode_lut.end()) {
		m_capture_mode = capture_mode_lut.at(capture_mode_str);
	} else {
		throw std::logic_error("Error reading config file (" + config_name + "): capture.mode '" +
		                       capture_mode_str + "' is not a valid mode.");
	}

	// Convert to nanoseconds
	m_capture_default_duration_ns =
	        m_config.get_scalar<uint32_t>("capture.default_duration", 5000) * 1000000LL;

	m_plugins_hostinfo = m_config.get_scalar<bool>("plugins_hostinfo", true);

	m_config.get_sequence<std::vector<rule_selection_config>>(m_rules_selection, "rules");
	m_config.get_sequence<std::vector<append_output_config>>(m_append_output, "append_output");

	// check if append_output matching conditions are sane, if not emit a warning
	for(auto const &entry : m_append_output) {
		if(entry.m_rule != "" && entry.m_tags.size() > 0) {
			std::string tag_list;

			for(auto const &tag : entry.m_tags) {
				tag_list += tag;
				tag_list += ", ";
			}

			tag_list.pop_back();

			falco_logger::log(falco_logger::level::WARNING,
			                  "An append_ouptut entry specifies both a rule (" + entry.m_rule +
			                          ") and a list of tags (" + tag_list + std::string("). ") +
			                          "This means that output will be appended only to the " +
			                          entry.m_rule + " rule and only if it has " +
			                          "all the tags: " + tag_list + ".");
		}
	}

	m_static_fields = m_config.get_scalar<std::map<std::string, std::string>>("static_fields", {});

	std::vector<std::string> load_plugins;

	bool load_plugins_node_defined = m_config.is_defined("load_plugins");
	m_config.get_sequence<std::vector<std::string>>(load_plugins, "load_plugins");

	std::list<falco_configuration::plugin_config> plugins;
	try {
		if(m_config.is_defined("plugins")) {
			m_config.get_sequence<std::list<falco_configuration::plugin_config>>(
			        plugins,
			        std::string("plugins"));
		}
	} catch(std::exception &e) {
		// Might be thrown due to not being able to open files
		throw std::logic_error("Error reading config file(" + config_name +
		                       "): could not load plugins config: " + e.what());
	}

	// If load_plugins was specified, only save plugins matching those in values
	m_plugins.clear();
	if(!load_plugins_node_defined) {
		// If load_plugins was not specified at all, every plugin is added.
		// The loading order is the same as the sequence in the YAML m_config.
		m_plugins = {plugins.begin(), plugins.end()};
	} else {
		// If load_plugins is specified, only plugins contained in its list
		// are added, with the same order as in the list.
		for(const auto &pname : load_plugins) {
			bool found = false;
			for(const auto &p : plugins) {
				if(pname == p.m_name) {
					m_plugins.push_back(p);
					found = true;
					break;
				}
			}
			if(!found) {
				throw std::logic_error("Cannot load plugin '" + pname +
				                       "': plugin config not found for given name");
			}
		}
	}

	m_watch_config_files = m_config.get_scalar<bool>("watch_config_files", true);
}

void falco_configuration::read_rules_file_directory(const std::string &path,
                                                    std::list<std::string> &rules_filenames,
                                                    std::list<std::string> &rules_folders) {
	fs::path rules_path = std::string(path);

	if(fs::is_directory(rules_path)) {
		rules_folders.push_back(path);

		// It's a directory. Read the contents, sort
		// alphabetically, and add every path to
		// rules_filenames
		std::vector<std::string> dir_filenames;

		const auto it_options = fs::directory_options::follow_directory_symlink |
		                        fs::directory_options::skip_permission_denied;

		for(auto const &dir_entry : fs::directory_iterator(rules_path, it_options)) {
			if(std::filesystem::is_regular_file(dir_entry.path())) {
				dir_filenames.push_back(dir_entry.path().string());
			}
		}

		std::sort(dir_filenames.begin(), dir_filenames.end());

		for(const std::string &ent : dir_filenames) {
			// only consider yaml files
			if(falco::utils::matches_wildcard("*.yaml", ent) ||
			   falco::utils::matches_wildcard("*.yml", ent)) {
				rules_filenames.push_back(ent);
			}
		}
	} else {
		// Assume it's a file and just add to
		// rules_filenames. If it can't be opened/etc that
		// will be reported later..
		// also, only consider yaml files
		if(falco::utils::matches_wildcard("*.yaml", path) ||
		   falco::utils::matches_wildcard("*.yml", path)) {
			rules_filenames.push_back(path);
		}
	}
}

static bool split(const std::string &str, char delim, std::pair<std::string, std::string> &parts) {
	size_t pos;

	if((pos = str.find_first_of(delim)) == std::string::npos) {
		return false;
	}
	parts.first = str.substr(0, pos);
	parts.second = str.substr(pos + 1);

	return true;
}

void falco_configuration::load_cmdline_config_files(
        const std::vector<std::string> &cmdline_options) {
	for(const std::string &option : cmdline_options) {
		// Set all config_files options
		if(option.rfind(yaml_helper::configs_key, 0) == 0) {
			set_cmdline_option(option);
		}
	}
}

void falco_configuration::init_cmdline_options(const std::vector<std::string> &cmdline_options) {
	for(const std::string &option : cmdline_options) {
		set_cmdline_option(option);
	}
}

void falco_configuration::set_cmdline_option(const std::string &opt) {
	std::pair<std::string, std::string> keyval;

	if(!split(opt, '=', keyval)) {
		throw std::logic_error("Error parsing config option \"" + opt +
		                       "\". Must be of the form key=val or key.subkey=val");
	}

	if(keyval.second[0] == '{' && keyval.second[keyval.second.size() - 1] == '}') {
		YAML::Node node = YAML::Load(keyval.second);
		m_config.set_object(keyval.first, node);
	} else {
		m_config.set_scalar(keyval.first, keyval.second);
	}
}
