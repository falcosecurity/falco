/*
Copyright (C) 2022 The Falco Authors.

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

#include <list>
#include <memory>
#include <string>
#include <set>
#include <utility>
#include "tbb/concurrent_queue.h"

#include <sinsp.h>
#include <filter_check_list.h>

#include <falco_engine.h>

class swappable_falco_engine
{
public:
	static std::string syscall_source;
	static std::string k8s_audit_source;

	class config {
	public:
		config();
		virtual ~config();

		bool contains_event_source(const std::string &source);

		bool json_output;
		std::string output_format;
		bool replace_container_info;
		std::set<std::string> event_sources;
		falco_common::priority_type min_priority;
		std::list<sinsp_plugin::info> plugin_infos;
		std::set<std::string> disabled_rule_substrings;
		std::set<std::string> disabled_rule_tags;
		std::set<std::string> enabled_rule_tags;
	};

	// Represents a rules file passed to replace() or validate().
	// The required_engine_version will be filled in upon a
	// successful call to replace() or validate().
	struct rulesfile {
		std::string name;
		std::string content;
		uint64_t required_engine_version;
	};

	// Helper to load a set of files from filenames
	static bool open_files(std::list<std::string> &filenames,
			       std::list<rulesfile> &rulesfiles,
			       std::string &errstr);

	swappable_falco_engine();
	virtual ~swappable_falco_engine();

	bool init(config &cfg, sinsp *inspector, std::string &errstr);

	std::shared_ptr<falco_engine> engine();

	filter_check_list &plugin_filter_checks();

	// Create a new engine, configure it using the saved config,
	// load the provided set of rules files, and queue it to
	// replace the current engine.
	//
	// This can be called from a different thread than the one
	// calling engine().
	//
        // Returns true on success, returns false and fills in
        // errstr otherwise.
	bool replace(const std::list<rulesfile> &rulesfiles, std::string &errstr);

	// Create a new engine, configure it, load the provided set of
	// rules files, but do *not* queue it to replace the current
	// engine.
	//
	// This can be called from a different thread than the one
	// calling engine().
	//
        // Returns true if all rules were valid. Returns false and fills in
        // errstr otherwise.
	bool validate(const std::list<rulesfile> &rulesfiles, std::string &errstr);

private:

	// Does everything but enqueue the new engine. Returns a
	// shared_ptr to a new falco_engine on success. On error the
	// shared_ptr will be empty and errstr will contain an error.
	std::shared_ptr<falco_engine> create_new(const std::list<rulesfile> &rulesfiles, std::string &errstr);

	sinsp *m_inspector;
	config m_config;
	filter_check_list m_plugin_filter_checks;

	std::shared_ptr<falco_engine> m_engine;

	// If non-empty the head item will be moved to m_falco_engine
	// with the next call to engine()
	tbb::concurrent_queue<std::shared_ptr<falco_engine>> m_pending_falco_engine;
};

