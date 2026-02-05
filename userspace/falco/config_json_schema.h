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

#pragma once

#define LONG_STRING_CONST(...) #__VA_ARGS__

const char config_schema_string[] = LONG_STRING_CONST(

{
    "$schema": "http://json-schema.org/draft-06/schema#",
    "$ref": "#/definitions/FalcoConfig",
    "definitions": {
        "FalcoConfig": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "append_output": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/AppendOutput"
                    }
                },
                "static_fields": {
                    "type": "object"
                },
                "config_files": {
                    "type": "array",
                    "items": {
                        "oneOf": [
                            {
                                "type": "string"
                            },
                            {
                                "type": "object",
                                "properties": {
                                    "path": {
                                        "type": "string"
                                    },
                                    "strategy": {
                                        "type": "string",
                                        "enum": [
                                            "append",
                                            "override",
                                            "add-only"
                                        ]
                                    }
                                },
                                "required": [
                                    "path"
                                ]
                            }
                        ]
                    }
                },
                "watch_config_files": {
                    "type": "boolean"
                },
                "plugins_hostinfo": {
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
                "capture": {
                    "$ref": "#/definitions/Capture"
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
                "buffer_format_base64": {
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
                "json_include_message_property": {
                    "type": "boolean"
                },
                "json_include_output_fields_property": {
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
                },
                "container_engines": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "docker": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "enabled": {
                                    "type": "boolean"
                                }
                            }
                        },
                        "cri": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "enabled": {
                                    "type": "boolean"
                                },
                                "sockets": {
                                    "type": "array",
                                    "items": {
                                        "type": "string"
                                    }
                                },
                                "disable_async": {
                                    "type": "boolean"
                                }
                            }
                        },
                        "podman": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "enabled": {
                                    "type": "boolean"
                                }
                            }
                        },
                        "lxc": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "enabled": {
                                    "type": "boolean"
                                }
                            }
                        },
                        "libvirt_lxc": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "enabled": {
                                    "type": "boolean"
                                }
                            }
                        },
                        "bpm": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "enabled": {
                                    "type": "boolean"
                                }
                            }
                        }
                    }
                }
            },
            "title": "FalcoConfig"
        },
        "AppendOutput": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "match": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "source": {
                            "type": "string"
                        },
                        "tags": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },
                        "rule": {
                            "type": "string"
                        }
                    }
                },
                "extra_output": {
                    "type": "string"
                },
                "extra_fields": {
                    "type": "array",
                    "items": {
                        "anyOf": [
                            {
                                "type": "object",
                                "additionalProperties": {
                                    "type": "string"
                                }
                            },
                            {
                                "type": "string"
                            }
                        ]
                    }
                },
                "suggested_output": {
                    "type": "boolean"
                }
            }
        },
        "Capture": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "enabled": {
                    "type": "boolean"
                },
                "path_prefix": {
                    "type": "string"
                },
                "mode": {
                    "type": "string",
                    "enum": [
                      "rules",
                      "all_rules"
                    ]
                },
                "default_duration": {
                    "type": "integer"
                }
            },
            "title": "Capture"
        },
        "BaseSyscalls": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "all": {
                    "type": "boolean"
                },
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
            "minProperties": 1,
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
                "modern_ebpf": {
                    "$ref": "#/definitions/ModernEbpf"
                },
                "replay": {
                    "$ref": "#/definitions/Replay"
                }
            },
            "required": [
                "kind"
            ],
            "title": "Engine"
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
            "minProperties": 1,
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
                },
                "thread_table_auto_purging_interval_s": {
                    "type": "integer"
                },
                "thread_table_auto_purging_thread_timeout_s": {
                    "type": "integer"
                },
                "snaplen": {
                    "type": "integer"
                }
            },
            "minProperties": 1,
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
            "minProperties": 1,
            "title": "FileOutput"
        },
        "Output": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "enabled": {
                    "type": "boolean"
                }
            },
            "minProperties": 1,
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
                },
                "max_consecutive_timeouts": {
                    "type": "integer"
                }
            },
            "minProperties": 1,
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
            "minProperties": 1,
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
                "kernel_event_counters_per_cpu_enabled": {
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
                },
                "jemalloc_stats_enabled": {
                    "type": "boolean"
                }
            },
            "minProperties": 1,
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
            "minProperties": 1,
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
                    "anyOf": [
                        {
                            "type": "object"
                        },
                        {
                            "type": "string"
                        },
                        {
                            "type": "null"
                        }
                    ]
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
            "minProperties": 1,
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
            "minProperties": 1,
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
            "minProperties": 1,
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
            "minProperties": 1,
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
            "minProperties": 1,
            "title": "Webserver"
        }
    }
}

);  // LONG_STRING_CONST macro
