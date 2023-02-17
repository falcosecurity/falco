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

#include "indexed_vector.h"

#include "options.h"
#include "../configuration.h"
#include "../stats_writer.h"
#ifndef MINIMAL_BUILD
#include "../grpc_server.h"
#include "../webserver.h"
#endif

#include <sinsp.h>

#include <string>
#include <memory>
#include <unordered_set>

namespace falco {
namespace app {

// Holds the state used and shared by the below methods that
// actually implement the application. Declared as a
// standalone class to allow for a bit of separation between
// application state and instance variables, and to also defer
// initializing this state until application::init.
struct state
{
    // Holds the info mapped for each loaded event source
    struct source_info
    {
        // The index of the given event source in the state's falco_engine,
        // as returned by falco_engine::add_source
        std::size_t engine_idx;
        // The filtercheck list containing all fields compatible
        // with the given event source
        filter_check_list filterchecks;
        // The inspector assigned to this event source. If in capture mode,
        // all event source will share the same inspector. If the event
        // source is a plugin one, the assigned inspector must have that
        // plugin registered in its plugin manager
        std::shared_ptr<sinsp> inspector;
    };

    state():
        loaded_sources(),
        enabled_sources(),
        source_infos(),
        plugin_configs(),
        selected_event_set(),
        selected_sc_set(),
        selected_tp_set(),
        syscall_buffer_bytes_size(DEFAULT_DRIVER_BUFFER_BYTES_DIM)
    {
        config = std::make_shared<falco_configuration>();
        engine = std::make_shared<falco_engine>();
        offline_inspector = std::make_shared<sinsp>();
        outputs = nullptr;
    }
    ~state() = default;
    state(state&&) = default;
    state& operator = (state&&) = default;
    state(const state&) = default;
    state& operator = (const state&) = default;

    std::string cmdline;
    falco::app::options options;

    std::shared_ptr<falco_configuration> config;
    std::shared_ptr<falco_outputs> outputs;
    std::shared_ptr<falco_engine> engine;

    // The set of loaded event sources (by default, the syscall event
    // source plus all event sources coming from the loaded plugins)
    std::unordered_set<std::string> loaded_sources;

    // The set of enabled event sources (can be altered by using
    // the --enable-source and --disable-source options)
    std::unordered_set<std::string> enabled_sources;

    // Used to load all plugins to get their info. In capture mode,
    // this is also used to open the capture file and read its events
    std::shared_ptr<sinsp> offline_inspector;

    // List of all the information mapped to each event source
    // indexed by event source name
    indexed_vector<source_info> source_infos;

    // List of all plugin configurations indexed by plugin name as returned
    // by their sinsp_plugin::name method
    indexed_vector<falco_configuration::plugin_config> plugin_configs;

    // Set of events we want the driver to capture
    libsinsp::events::set<ppm_event_code> selected_event_set;

    // Set of syscalls we want the driver to capture
    libsinsp::events::set<ppm_sc_code> selected_sc_set;

    // Set of tracepoints we want the driver to capture
    libsinsp::events::set<ppm_tp_code> selected_tp_set;

    // Dimension of the syscall buffer in bytes.
    uint64_t syscall_buffer_bytes_size;

#ifndef MINIMAL_BUILD
    falco::grpc::server grpc_server;
    std::thread grpc_server_thread;

    falco_webserver webserver;
#endif

    inline bool is_capture_mode() const 
    {
        return !options.trace_filename.empty();
    }

    inline bool is_gvisor_enabled() const
    {
        return !options.gvisor_config.empty();
    }
};

}; // namespace app
}; // namespace falco
