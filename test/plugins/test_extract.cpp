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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <engine/source_plugin/plugin_info.h>

static const char *pl_required_api_version = PLUGIN_API_VERSION_STR;
static const char *pl_name_base            = "test_extract";
static char pl_name[1024];
static const char *pl_desc                 = "Test Plugin For Regression Tests";
static const char *pl_contact              = "github.com/falcosecurity/falco";
static const char *pl_version              = "0.1.0";
static const char *pl_extract_sources      = "[\"test_source\"]";
static const char *pl_fields               = "[{\"type\": \"uint64\", \"name\": \"test.field\", \"desc\": \"Describing test field\"}]";

// This struct represents the state of a plugin. Just has a placeholder string value.
typedef struct plugin_state
{
} plugin_state;

extern "C"
const char* plugin_get_required_api_version()
{
	return pl_required_api_version;
}

extern "C"
const char* plugin_get_name()
{
	// Add a random-ish suffix to the end, as some tests load
	// multiple copies of this plugin
	snprintf(pl_name, sizeof(pl_name)-1, "%s%ld", pl_name_base, random());
	return pl_name;
}

extern "C"
const char* plugin_get_description()
{
	return pl_desc;
}

extern "C"
const char* plugin_get_contact()
{
	return pl_contact;
}

extern "C"
const char* plugin_get_version()
{
	return pl_version;
}

extern "C"
const char* plugin_get_extract_event_sources()
{
	return pl_extract_sources;
}

extern "C"
const char* plugin_get_fields()
{
	return pl_fields;
}

extern "C"
const char* plugin_get_last_error(ss_plugin_t* s)
{
	return NULL;
}

extern "C"
ss_plugin_t* plugin_init(const char* config, int32_t* rc)
{
	// Note: Using new/delete is okay, as long as the plugin
	// framework is not deleting the memory.
	plugin_state *ret = new plugin_state();
	*rc = SS_PLUGIN_SUCCESS;
	return ret;
}

extern "C"
void plugin_destroy(ss_plugin_t* s)
{
	plugin_state *ps = (plugin_state *) s;

	delete(ps);
}

extern "C"
int32_t plugin_extract_fields(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields)
{
	return SS_PLUGIN_SUCCESS;
}
