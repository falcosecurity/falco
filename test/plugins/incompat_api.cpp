/*
Copyright (C) 2021 The Falco Authors.

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

#include <string.h>
#include <stdlib.h>

// Don't need any function other than plugin_get_required_api_version,
// plugin load will fail after that.
static const char *pl_required_api_version = "10000000.0.0";

extern "C"
const char* plugin_get_required_api_version()
{
	return pl_required_api_version;
}
