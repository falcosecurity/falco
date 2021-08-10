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

/*
  This header file provides a C-only interface to the falco engine,
  suitable for embedding in other programs as a shared library. This
  interface handles:
  - Loading Rules Content
  - Enabling/Disabling syscall/k8s_audit event sources.
  - Loading and configuring source/extractor plugins
  - Starting/Stopping the event processing loop.

  After setup, the main interface involves receiving "results" when
  syscall/k8s_audit/plugin events match rules.

  This interface does not provide as many features as the c++
  falco_engine interface, such as interfaces to list rules, segregate
  rules by "ruleset", enabling/disabling specific rules etc.

  Output handling (e.g. routing alerts to files, stdout, webhook,
  slack, etc) is not covered by this interface. After receiving a
  result, a program could use a program like falcosidekick for a rich
  set of output handling methods.

*/

#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A handle to an embeddable falco engine */
typedef void falco_engine_embed_t;

/* Defined return values from API functions. */
enum falco_engine_embed_rc
{
	/* No Error */
	FE_EMB_RC_OK = 0,
	FE_EMB_RC_ERROR = 1,
	FE_EMB_RC_EOF = 2,
};

/* Defined event sources. */
enum falco_engine_embed_evt_source
{
	FE_EMB_SRC_NONE = 0,
	FE_EMB_SRC_SYSCALL = 1,
	FE_EMB_K8S_AUDIT = 2,
	FE_EMB_PLUGINS = 3,   // This includes any event from any plugin
};

/* Represents a result (e.g. an event matching a falco rule)

   When returned by a call to next_result(), the struct, as well as
   every allocated char * within the struct, is allocated via a call
   to malloc() and must be freed via a call to free().
*/
typedef struct falco_engine_embed_result
{
	// The rule that matched the event
	char *rule;

	// The event source of the event that matched the rule
	char *event_source;

	// An int containing a falco_common::priority_type value of
	// the priority of the matching rule.
	int32_t priority_num;

	// A copy of the rule's output string, *without* any
	// fields (e.g. %proc.name, ...) resolved to values.
	char *output_format_str;

	// An output string, starting with the rule's output string
	// with all fields resolved to values.
	char *output_str;

	// An allocated array of allocated field names from the output
	// string. Additional fields + values may be included in
	// addition to those in the output string, to aid in
	// debugging. Item i in this array maps to item i in
	// output_values.
	char **output_fields;

	// An allocated array of allocated field values from the
	// output string. Additional fields + values may be included in
	// addition to those in the output string, to aid in
	// debugging. Item i in this array maps to item i in
	// output_fields.
	char **output_values;

	// The length of output_fields/output_values
	uint32_t num_output_values;
} falco_engine_embed_result;

/* A utility function to free a falco_engine_embed_result struct and
 * its allocated strings returned by a call to next_result() */
void falco_engine_embed_free_result(falco_engine_embed_result *result);

// Interface to interact with an embeddable falco engine.

// NOTE: For all functions below that return a char *, the memory
// pointed to by the char * is allocated using malloc() and should be
// freed by the caller using free().

// Return the embedded engine version.
//
// Return value: a version string, in the following format:
//        "<major>.<minor>.<patch>", e.g. "1.2.3".
// This interface is compatible following semver conventions:
// <major> changes for incompatible api changes, <minor> for
// backwards-compatible additions, <patch> for compatible bug
// fixes.
char* falco_engine_embed_get_version();

// Initialize a falco engine.
//
// Arguments:
// - rc: pointer to an integer containing a falco_engine_embed_rc value.
//
// Return value: pointer to the engine state that is passed to
// other API functions.
falco_engine_embed_t* falco_engine_embed_init(int32_t *rc);

// Destroy a falco engine. This frees any resources allocated in
// init(). If open() has been called, close() should be called before
// destroy().
//
// Arguments:
// - engine: returned by a prior succesful call to init().
// - errstr: on error, errstr will point to an allocated
//   string with additional details on the errror. The string
//   must be freed via a call to free().
//
// Return value: an integer containing a falco_engine_embed_rc
// value.
int32_t falco_engine_embed_destroy(falco_engine_embed_t *engine, char *errstr);

// Load either a falco source or extractor plugin.
//
// Arguments:
// - engine: returned by a prior succesful call to init().
// - path: a file path pointing to a dynamic library that
//   can be dlopen()ed.
// - init_config: a string that will be passed to the plugin's
//   init() function.
// - open_params: a string that will be passed to the
//   plugin's open() function.
// - errstr: on error, errstr will point to an allocated
//   string with additional details on the errror. The string
//   must be freed via a call to free().
//
// Return value: an integer containing a falco_engine_embed_rc
// value.
int32_t falco_engine_embed_load_plugin(falco_engine_embed_t *engine,
				       const char *path,
				       const char* init_config,
				       const char* open_params,
				       char **errstr);

// Load the provided rules content. These rules are applied on
// top of any previously loaded rules content
// (e.g. appending/overriding rule/macro/list objects as
// specified via "append:" properties)
//
// NOTE: Plugins should be loaded before any rules are loaded.
//
// Arguments:
// - engine: returned by a prior succesful call to init().
// - rules_content: a null-terminated string containing
//   yaml rules content.
// - errstr: on error, errstr will point to an allocated
//   string with additional details on the errror. The string
//   must be freed via a call to free().
//
// Return value: an integer containing a falco_engine_embed_rc
// value.
int32_t falco_engine_embed_load_rules_content(falco_engine_embed_t *engine,
					      const char *rules_content,
					      char **errstr);

// Enable/disable an event source.
// By default all event sources are enabled. This function
// enables/disables specific event sources.
//
// Arguments:
// - engine: returned by a prior succesful call to init().
// - source: an int containing a falco_engine_embed_evt_source value.
// - enabled: whether to enable or disable the provided source
// - errstr: on error, errstr will point to an allocated
//   string with additional details on the errror. The string
//   must be freed via a call to free().
//
// Return value: an integer containing a falco_engine_embed_rc
// value.
int32_t falco_engine_embed_enable_source(falco_engine_embed_t *engine,
					 int32_t source,
					 bool enabled,
					 char **errstr);

// Open the engine, which starts event processing and matching
// against the loaded set of rules.
//
// Arguments:
// - engine: returned by a prior succesful call to init().
// - errstr: on error, errstr will point to an allocated
//   string with additional details on the errror. The string
//   must be freed via a call to free().
//
// Return value: an integer containing a falco_engine_embed_rc
// value.
int32_t falco_engine_embed_open(falco_engine_embed_t *engine,
				char **errstr);

// Close the engine, which stops event processing.
//
// Arguments:
// - engine: returned by a prior succesful call to init().
// - errstr: on error, errstr will point to an allocated
//   string with additional details on the errror. The string
//   must be freed via a call to free().
//
// Return value: an integer containing a falco_engine_embed_rc
// value.
int32_t falco_engine_embed_close(falco_engine_embed_t *engine,
				 char **errstr);

// Receive the next result (e.g. an event that matched a
// rule). This function blocks until the next result is
// available. close() is called, or an error occurs.
//
// Arguments:
// - engine: returned by a prior succesful call to init().
// - result: a pointer to a falco_engine_embed_result struct
//   pointer. On success, a struct will be allocated, and filled in
//   with allocated char* values, and the pointer updated to point to
//   the allocated struct.
// - errstr: on error, errstr will point to an allocated
//   string with additional details on the errror. The string
//   must be freed via a call to free().
//
// Return value: an integer containing a falco_engine_embed_rc
// value.
int32_t falco_engine_embed_next_result(falco_engine_embed_t *engine,
				       falco_engine_embed_result **result,
				       char **errstr);
#ifdef __cplusplus
} // extern "C"
#endif

