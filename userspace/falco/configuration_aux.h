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

#pragma once

//
// json_output_properties flags
//
#define CONFIG_JSON_OUTPUT_PROPERTIES_OUTPUT (1 << 0)
#define CONFIG_JSON_OUTPUT_PROPERTIES_PRIORITY (1 << 1)
#define CONFIG_JSON_OUTPUT_PROPERTIES_TAGS (1 << 2)
#define CONFIG_JSON_OUTPUT_PROPERTIES_HOSTNAME (1 << 3)
#define CONFIG_JSON_OUTPUT_PROPERTIES_SOURCE (1 << 4)
#define CONFIG_JSON_OUTPUT_PROPERTIES_OUTPUT_FIELDS (1 << 5)
#define CONFIG_JSON_OUTPUT_PROPERTIES_OUTPUT_OLD_OPTION (1 << 6) // todo: deprecate for Falco 0.37
#define CONFIG_JSON_OUTPUT_PROPERTIES_TAGS_OLD_OPTION (1 << 7) // todo: deprecate for Falco 0.37
