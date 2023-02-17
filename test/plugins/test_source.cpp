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
#include <stdio.h>
#include <stdlib.h>

#include <engine/source_plugin/plugin_info.h>

static const char *pl_required_api_version = PLUGIN_API_VERSION_STR;
static uint32_t    pl_id                   = 999;
static const char *pl_name                 = "test_source";
static const char *pl_desc                 = "Test Plugin For Regression Tests";
static const char *pl_contact              = "github.com/falcosecurity/falco";
static const char *pl_version              = "0.1.0";
static const char *pl_event_source         = "test_source";
static const char *pl_fields               = "[]";

// This struct represents the state of a plugin. Just has a placeholder string value.
typedef struct plugin_state
{
} plugin_state;

typedef struct instance_state
{
} instance_state;

extern "C"
const char* plugin_get_required_api_version()
{
	return pl_required_api_version;
}

extern "C"
uint32_t plugin_get_id()
{
	return pl_id;
}

extern "C"
const char* plugin_get_name()
{
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
const char* plugin_get_event_source()
{
	return pl_event_source;
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
ss_instance_t* plugin_open(ss_plugin_t* s, const char* params, int32_t* rc)
{
	// Note: Using new/delete is okay, as long as the plugin
	// framework is not deleting the memory.
	instance_state *ret = new instance_state();
	*rc = SS_PLUGIN_SUCCESS;

	return ret;
}

extern "C"
void plugin_close(ss_plugin_t* s, ss_instance_t* i)
{
	instance_state *istate = (instance_state *) i;

	delete(istate);
}

extern "C"
int32_t plugin_next_batch(ss_plugin_t* s, ss_instance_t* i, uint32_t *nevts, ss_plugin_event **evts)
{
	return SS_PLUGIN_EOF;
}

// This plugin does not implement plugin_next_batch, due to the lower
// overhead of calling C functions from the plugin framework compared
// to calling Go functions.

extern "C"
const char *plugin_event_to_string(ss_plugin_t *s, const uint8_t *data, uint32_t datalen)
{
	return "";
}

extern "C"
int32_t plugin_extract_fields(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields)
{
	return SS_PLUGIN_SUCCESS;
}
