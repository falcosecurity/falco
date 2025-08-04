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

#pragma once

#define LONG_STRING_CONST(...) #__VA_ARGS__

const char rule_schema_string[] = LONG_STRING_CONST(

{
    "$schema": "http://json-schema.org/draft-06/schema#",
    "type": "array",
    "items": {
        "$ref": "#/definitions/FalcoRule"
    },
    "definitions": {
        "FalcoRule": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "required_engine_version": {
                    "type": "string"
                },
                "required_plugin_versions": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/RequiredPluginVersion"
                    }
                },
                "macro": {
                    "type": "string"
                },
                "condition": {
                    "type": "string"
                },
                "list": {
                    "type": "string"
                },
                "items": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/Item"
                    }
                },
                "rule": {
                    "type": "string"
                },
                "desc": {
                    "type": "string"
                },
                "enabled": {
                    "type": "boolean"
                },
                "output": {
                    "type": "string"
                },
                "append": {
                    "type": "boolean"
                },
                "priority": {
                    "$ref": "#/definitions/Priority"
                },
                "capture": {
                    "type": "boolean"
                },
                "capture_duration": {
                    "type": "integer"
                },
                "source": {
	                "type": "string"
                },
                "exceptions": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/Exception"
                    }
                },
                "override": {
                    "$ref": "#/definitions/Override"
                },
                "tags": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                }
            },
            "required": [],
            "title": "FalcoRule"
        },
        "Item": {
            "anyOf": [
                {
                    "type": "integer"
                },
                {
                    "type": "string"
                }
            ],
            "title": "Item"
        },
        "Exception": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "name": {
                    "type": "string"
                },
                "fields": {},
                "comps": {},
                "values": {}
            },
            "required": [
                "name"
            ],
            "title": "Exception"
        },
        "Priority": {
            "type": "string",
            "enum": [
                "EMERGENCY",
                "ALERT",
                "CRITICAL",
                "ERROR",
                "WARNING",
                "NOTICE",
                "INFO",
                "INFORMATIONAL",
                "DEBUG"
            ],
            "title": "Priority"
        },
        "OverriddenItem": {
            "type": "string",
            "enum": [
                "append",
                "replace"
            ],
            "title": "Priority"
        },
        "Override": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "items": {
                    "$ref": "#/definitions/OverriddenItem"
                },
                "desc": {
                    "$ref": "#/definitions/OverriddenItem"
                },
                "condition": {
                    "$ref": "#/definitions/OverriddenItem"
                },
                "output": {
                    "$ref": "#/definitions/OverriddenItem"
                },
                "priority": {
                    "$ref": "#/definitions/OverriddenItem"
                },
                "enabled": {
                    "$ref": "#/definitions/OverriddenItem"
                },
                "exceptions": {
                    "$ref": "#/definitions/OverriddenItem"
                }
            },
            "minProperties": 1,
            "title": "Override"
        },
        "RequiredPluginVersion": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "name": {
                    "type": "string"
                },
                "version": {
                    "type": "string"
                },
                "alternatives": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/Alternative"
                    }
                }
            },
            "required": [
                "name",
                "version"
            ],
            "title": "RequiredPluginVersion"
        },
        "Alternative": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
	            "name": {
		            "type": "string"
	            },
	            "version": {
		            "type": "string"
	            }
            },
            "required": [
	            "name",
	            "version"
            ],
            "title": "Alternative"
        }
    }
}

);  // LONG_STRING_CONST macro
