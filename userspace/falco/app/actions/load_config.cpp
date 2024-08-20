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

#include "actions.h"
#include "falco_utils.h"

#include <json/json.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include <valijson/adapters/jsoncpp_adapter.hpp>
#include <valijson/adapters/yaml_cpp_adapter.hpp>
#pragma GCC diagnostic pop
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>

using namespace falco::app;
using namespace falco::app::actions;

static const std::string schema_json_string = R"(
{
    "$schema": "http://json-schema.org/draft-06/schema#",
    "$ref": "#/definitions/FalcoConfig",
    "definitions": {
        "FalcoConfig": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "config_files": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "watch_config_files": {
                    "type": "boolean"
                },
                "rules_files": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "rule_files": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "rules": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/Rule"
                    }
                },
                "engine": {
                    "$ref": "#/definitions/Engine"
                },
                "load_plugins": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "plugins": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/Plugin"
                    }
                },
                "time_format_iso_8601": {
                    "type": "boolean"
                },
                "priority": {
                    "type": "string"
                },
                "json_output": {
                    "type": "boolean"
                },
                "json_include_output_property": {
                    "type": "boolean"
                },
                "json_include_tags_property": {
                    "type": "boolean"
                },
                "buffered_outputs": {
                    "type": "boolean"
                },
                "rule_matching": {
                    "type": "string"
                },
                "outputs_queue": {
                    "$ref": "#/definitions/OutputsQueue"
                },
                "stdout_output": {
                    "$ref": "#/definitions/Output"
                },
                "syslog_output": {
                    "$ref": "#/definitions/Output"
                },
                "file_output": {
                    "$ref": "#/definitions/FileOutput"
                },
                "http_output": {
                    "$ref": "#/definitions/HTTPOutput"
                },
                "program_output": {
                    "$ref": "#/definitions/ProgramOutput"
                },
                "grpc_output": {
                    "$ref": "#/definitions/Output"
                },
                "grpc": {
                    "$ref": "#/definitions/Grpc"
                },
                "webserver": {
                    "$ref": "#/definitions/Webserver"
                },
                "log_stderr": {
                    "type": "boolean"
                },
                "log_syslog": {
                    "type": "boolean"
                },
                "log_level": {
                    "type": "string"
                },
                "libs_logger": {
                    "$ref": "#/definitions/LibsLogger"
                },
                "output_timeout": {
                    "type": "integer"
                },
                "syscall_event_timeouts": {
                    "$ref": "#/definitions/SyscallEventTimeouts"
                },
                "syscall_event_drops": {
                    "$ref": "#/definitions/SyscallEventDrops"
                },
                "metrics": {
                    "$ref": "#/definitions/Metrics"
                },
                "base_syscalls": {
                    "$ref": "#/definitions/BaseSyscalls"
                },
                "falco_libs": {
                    "$ref": "#/definitions/FalcoLibs"
                }
            },
            "title": "FalcoConfig"
        },
        "BaseSyscalls": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "custom_set": {
                    "type": "array",
                    "items": {
    			"type": "string"
		    }
                },
                "repair": {
                    "type": "boolean"
                }
            },
            "anyOf": [
		{
 		    "required": [
			"custom_set"
		    ]
                },
		{
		    "required": [
			"repair"
		    ]
		}
	    ],
            "title": "BaseSyscalls"
        },
        "Engine": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "kind": {
                    "type": "string"
                },
                "kmod": {
                    "$ref": "#/definitions/Kmod"
                },
                "ebpf": {
                    "$ref": "#/definitions/Ebpf"
                },
                "modern_ebpf": {
                    "$ref": "#/definitions/ModernEbpf"
                },
                "replay": {
                    "$ref": "#/definitions/Replay"
                },
                "gvisor": {
                    "$ref": "#/definitions/Gvisor"
                }
            },
            "required": [
                "kind"
            ],
            "title": "Engine"
        },
        "Ebpf": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "probe": {
                    "type": "string"
                },
                "buf_size_preset": {
                    "type": "integer"
                },
                "drop_failed_exit": {
                    "type": "boolean"
                }
            },
            "required": [
                "probe"
            ],
            "title": "Ebpf"
        },
        "Gvisor": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "config": {
                    "type": "string"
                },
                "root": {
                    "type": "string"
                }
            },
            "required": [
                "config",
                "root"
            ],
            "title": "Gvisor"
        },
        "Kmod": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "buf_size_preset": {
                    "type": "integer"
                },
                "drop_failed_exit": {
                    "type": "boolean"
                }
            },
            "title": "Kmod"
        },
        "ModernEbpf": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "cpus_for_each_buffer": {
                    "type": "integer"
                },
                "buf_size_preset": {
                    "type": "integer"
                },
                "drop_failed_exit": {
                    "type": "boolean"
                }
            },
            "title": "ModernEbpf"
        },
        "Replay": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "capture_file": {
                    "type": "string"
                }
            },
            "required": [
                "capture_file"
            ],
            "title": "Replay"
        },
        "FalcoLibs": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "thread_table_size": {
                    "type": "integer"
                }
            },
            "required": [
                "thread_table_size"
            ],
            "title": "FalcoLibs"
        },
        "FileOutput": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "enabled": {
                    "type": "boolean"
                },
                "keep_alive": {
                    "type": "boolean"
                },
                "filename": {
                    "type": "string"
                }
            },
            "required": [
                "enabled",
                "filename",
                "keep_alive"
            ],
            "title": "FileOutput"
        },
        "Grpc": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "enabled": {
                    "type": "boolean"
                },
                "bind_address": {
                    "type": "string"
                },
                "threadiness": {
                    "type": "integer"
                }
            },
            "required": [
                "bind_address",
                "enabled",
                "threadiness"
            ],
            "title": "Grpc"
        },
        "Output": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "enabled": {
                    "type": "boolean"
                }
            },
            "required": [
                "enabled"
            ],
            "title": "Output"
        },
        "HTTPOutput": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "enabled": {
                    "type": "boolean"
                },
                "url": {
                    "type": "string",
                    "format": "uri",
                    "qt-uri-protocols": [
                        "http"
                    ]
                },
                "user_agent": {
                    "type": "string"
                },
                "insecure": {
                    "type": "boolean"
                },
                "ca_cert": {
                    "type": "string"
                },
                "ca_bundle": {
                    "type": "string"
                },
                "ca_path": {
                    "type": "string"
                },
                "mtls": {
                    "type": "boolean"
                },
                "client_cert": {
                    "type": "string"
                },
                "client_key": {
                    "type": "string"
                },
                "echo": {
                    "type": "boolean"
                },
                "compress_uploads": {
                    "type": "boolean"
                },
                "keep_alive": {
                    "type": "boolean"
                }
            },
            "required": [
                "ca_bundle",
                "ca_cert",
                "ca_path",
                "client_cert",
                "client_key",
                "compress_uploads",
                "echo",
                "enabled",
                "insecure",
                "keep_alive",
                "mtls",
                "url",
                "user_agent"
            ],
            "title": "HTTPOutput"
        },
        "LibsLogger": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "enabled": {
                    "type": "boolean"
                },
                "severity": {
                    "type": "string"
                }
            },
            "required": [
                "enabled",
                "severity"
            ],
            "title": "LibsLogger"
        },
        "Metrics": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "enabled": {
                    "type": "boolean"
                },
                "interval": {
                    "type": "string"
                },
                "output_rule": {
                    "type": "boolean"
                },
                "output_file": {
                    "type": "string"
                },
                "rules_counters_enabled": {
                    "type": "boolean"
                },
                "resource_utilization_enabled": {
                    "type": "boolean"
                },
                "state_counters_enabled": {
                    "type": "boolean"
                },
                "kernel_event_counters_enabled": {
                    "type": "boolean"
                },
                "libbpf_stats_enabled": {
                    "type": "boolean"
                },
                "plugins_metrics_enabled": {
                    "type": "boolean"
                },
                "convert_memory_to_mb": {
                    "type": "boolean"
                },
                "include_empty_values": {
                    "type": "boolean"
                }
            },
            "required": [
                "convert_memory_to_mb",
                "enabled",
                "include_empty_values",
                "interval",
                "kernel_event_counters_enabled",
                "libbpf_stats_enabled",
                "output_file",
                "output_rule",
                "plugins_metrics_enabled",
                "resource_utilization_enabled",
                "rules_counters_enabled",
                "state_counters_enabled"
            ],
            "title": "Metrics"
        },
        "OutputsQueue": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "capacity": {
                    "type": "integer"
                }
            },
            "required": [
                "capacity"
            ],
            "title": "OutputsQueue"
        },
        "Plugin": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "name": {
                    "type": "string"
                },
                "library_path": {
                    "type": "string"
                },
                "init_config": {
                    "type": "string"
                },
                "open_params": {
                    "type": "string"
                }
            },
            "required": [
                "library_path",
                "name"
            ],
            "title": "Plugin"
        },
        "ProgramOutput": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "enabled": {
                    "type": "boolean"
                },
                "keep_alive": {
                    "type": "boolean"
                },
                "program": {
                    "type": "string"
                }
            },
            "required": [
                "enabled",
                "keep_alive",
                "program"
            ],
            "title": "ProgramOutput"
        },
        "Rule": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "disable": {
                    "$ref": "#/definitions/Able"
                },
                "enable": {
                    "$ref": "#/definitions/Able"
                }
            },
            "required": [],
            "title": "Rule"
        },
        "Able": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "rule": {
                    "type": "string"
                },
		"tag": {
		    "type": "string"
		}
            },
            "title": "Able"
        },
        "SyscallEventDrops": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "threshold": {
                    "type": "number"
                },
                "actions": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "rate": {
                    "type": "number"
                },
                "max_burst": {
                    "type": "integer"
                },
                "simulate_drops": {
                    "type": "boolean"
                }
            },
            "required": [
                "actions",
                "max_burst",
                "rate",
                "simulate_drops",
                "threshold"
            ],
            "title": "SyscallEventDrops"
        },
        "SyscallEventTimeouts": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "max_consecutives": {
                    "type": "integer"
                }
            },
            "required": [
                "max_consecutives"
            ],
            "title": "SyscallEventTimeouts"
        },
        "Webserver": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "enabled": {
                    "type": "boolean"
                },
                "threadiness": {
                    "type": "integer"
                },
                "listen_port": {
                    "type": "integer"
                },
                "listen_address": {
                    "type": "string"
                },
                "k8s_healthz_endpoint": {
                    "type": "string"
                },
                "prometheus_metrics_enabled": {
                    "type": "boolean"
                },
                "ssl_enabled": {
                    "type": "boolean"
                },
                "ssl_certificate": {
                    "type": "string"
                }
            },
            "required": [
                "enabled",
                "k8s_healthz_endpoint",
                "listen_address",
                "listen_port",
                "prometheus_metrics_enabled",
                "ssl_certificate",
                "ssl_enabled",
                "threadiness"
            ],
            "title": "Webserver"
        }
    }
}
)";

static std::string validate_config_files(const std::string &config_file)
{
	// Parse schema to a Json::Value, just once.
	static Json::Value schemaJson;
	if (schemaJson.empty())
	{
		if(!Json::Reader().parse(schema_json_string, schemaJson) || schemaJson.type() != Json::objectValue)
		{
			throw falco_exception("failed to parse config schema");
		}
	}

	// Parse config to a YAML::Node. If we reach this point,
	// this cannot fail because we have already parsed the config file
	YAML::Node configYAML = YAML::LoadFile(config_file);

	// Validate the yaml against our json schema
	valijson::Schema schemaDef;
	valijson::SchemaParser schemaParser;
	valijson::Validator validator(valijson::Validator::kWeakTypes);
	valijson::ValidationResults validationResults;
	valijson::adapters::YamlCppAdapter configAdapter(configYAML);
	valijson::adapters::JsonCppAdapter schemaAdapter(schemaJson);
	schemaParser.populateSchema(schemaAdapter, schemaDef);

	if (!validator.validate(schemaDef, configAdapter, &validationResults))
	{
		valijson::ValidationResults::Error error;
		// report only the top-most error
		if (validationResults.popError(error))
		{
			return std::string("validation failed for ")
						 + std::accumulate(error.context.begin(), error.context.end(), std::string(""))
						 + ": "
						 + error.description;
		}
		return "validation failed";
	}
	return "validated";
}

// applies legacy/in-deprecation options to the current state
static falco::app::run_result apply_deprecated_options(const falco::app::state& s)
{
	return run_result::ok();
}

falco::app::run_result falco::app::actions::load_config(const falco::app::state& s)
{
	// List of loaded conf files, ie: s.options.conf_filename
	// plus all the `config_files` expanded list of configs.
	std::vector<std::string> loaded_conf_files;
	try
	{
		if (!s.options.conf_filename.empty())
		{
			s.config->init_from_file(s.options.conf_filename, loaded_conf_files, s.options.cmdline_config_options);
		}
		else
		{
			// Is possible to have an empty config file when we want to use some command line
			// options like `--help`, `--version`, ...
			// The configs used in `load_yaml` will be initialized to the default values.
			s.config->init_from_content("", s.options.cmdline_config_options);
		}
	}
	catch (std::exception& e)
	{
		return run_result::fatal(e.what());
	}

	// log after config init because config determines where logs go
	falco_logger::set_time_format_iso_8601(s.config->m_time_format_iso_8601);
	falco_logger::log(falco_logger::level::INFO, "Falco version: " + std::string(FALCO_VERSION) + " (" + std::string(FALCO_TARGET_ARCH) + ")\n");
	if (!s.cmdline.empty())
	{
		falco_logger::log(falco_logger::level::DEBUG, "CLI args: " + s.cmdline);
	}
	if (!s.options.conf_filename.empty())
	{
		falco_logger::log(falco_logger::level::INFO, "Falco initialized with configuration files:\n");
		for (const auto& path : loaded_conf_files)
		{
			auto validation_status = validate_config_files(path);
			falco_logger::log(falco_logger::level::INFO, std::string("   ") + path + " | " + validation_status + "\n");
		}
	}

	s.config->m_buffered_outputs = !s.options.unbuffered_outputs;

	return apply_deprecated_options(s);
}

falco::app::run_result falco::app::actions::require_config_file(const falco::app::state& s)
{
#ifndef __EMSCRIPTEN__
	if (s.options.conf_filename.empty())
	{
#ifndef BUILD_TYPE_RELEASE
		return run_result::fatal(std::string("You must create a config file at ")  + FALCO_SOURCE_CONF_FILE + ", " + FALCO_INSTALL_CONF_FILE + " or by passing -c");
#else // BUILD_TYPE_RELEASE
		return run_result::fatal(std::string("You must create a config file at ")  + FALCO_INSTALL_CONF_FILE + " or by passing -c");
#endif // BUILD_TYPE_RELEASE
	}
#endif // __EMSCRIPTEN__
	return run_result::ok();
}