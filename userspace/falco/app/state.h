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

#pragma once

#include "indexed_vector.h"

#include "options.h"
#include "restart_handler.h"
#include "../configuration.h"
#include "../stats_writer.h"
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
#include "../grpc_server.h"
#include "../webserver.h"
#endif

#include <libsinsp/sinsp.h>

#include <string>
#include <memory>
#include <atomic>
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
        source_info():
            engine_idx(-1),
            filterchecks(new filter_check_list()),
            inspector(nullptr) { }
        source_info(source_info&&) = default;
        source_info& operator = (source_info&&) = default;
        source_info(const source_info&) = default;
        source_info& operator = (const source_info&) = default;

        // The index of the given event source in the state's falco_engine,
        // as returned by falco_engine::add_source
        std::size_t engine_idx;
        // The filtercheck list containing all fields compatible
        // with the given event source
        std::shared_ptr<filter_check_list> filterchecks;
        // The inspector assigned to this event source. If in capture mode,
        // all event source will share the same inspector. If the event
        // source is a plugin one, the assigned inspector must have that
        // plugin registered in its plugin manager
        std::shared_ptr<sinsp> inspector;
    };

    state():
        restart(false),
        config(std::make_shared<falco_configuration>()),
        outputs(nullptr),
        engine(std::make_shared<falco_engine>()),
        loaded_sources(),
        enabled_sources(),
        offline_inspector(std::make_shared<sinsp>()),
        source_infos(),
        plugin_configs(),
        selected_sc_set(),
        syscall_buffer_bytes_size(DEFAULT_DRIVER_BUFFER_BYTES_DIM),
        restarter(nullptr)
    {
    }

    state(const std::string& cmd, const falco::app::options& opts): state()
    {
        cmdline = cmd;
        options = opts;
    }

    ~state() = default;

    std::string cmdline;
    falco::app::options options;
    std::atomic<bool> restart;


    std::shared_ptr<falco_configuration> config;
    std::shared_ptr<falco_outputs> outputs;
    std::shared_ptr<falco_engine> engine;

    // The set of loaded event sources (by default, the syscall event
    // source plus all event sources coming from the loaded plugins).
    // note: this has to be a vector to preserve the loading order,
    // however it's not supposed to contain duplicate values.
    std::vector<std::string> loaded_sources;

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

    // Set of syscalls we want the driver to capture
    libsinsp::events::set<ppm_sc_code> selected_sc_set;

    // Dimension of the syscall buffer in bytes.
    uint64_t syscall_buffer_bytes_size;

    // Helper responsible for watching of handling hot application restarts
    std::shared_ptr<restart_handler> restarter;

#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
    falco::grpc::server grpc_server;
    std::thread grpc_server_thread;

    falco_webserver webserver;
#endif

    inline bool is_capture_mode() const
    {
        return config->m_engine_mode == engine_kind_t::REPLAY;
    }

    inline bool is_gvisor() const
    {
        return config->m_engine_mode == engine_kind_t::GVISOR;
    }

    inline bool is_kmod() const
    {
        return config->m_engine_mode == engine_kind_t::KMOD;
    }

    inline bool is_ebpf() const
    {
        return config->m_engine_mode == engine_kind_t::EBPF;
    }

    inline bool is_modern_ebpf() const
    {
        return config->m_engine_mode == engine_kind_t::MODERN_EBPF;
    }

    inline bool is_nodriver() const
    {
        return config->m_engine_mode == engine_kind_t::NODRIVER;
    }

    inline bool is_source_enabled(const std::string& src) const
    {
        return enabled_sources.find(falco_common::syscall_source) != enabled_sources.end();
    }

    inline bool is_driver_drop_failed_exit_enabled() const
    {
	bool drop_failed;
	switch (config->m_engine_mode)
	{
	case engine_kind_t::KMOD:
		drop_failed = config->m_kmod.m_drop_failed_exit;
		break;
	case engine_kind_t::EBPF:
		drop_failed = config->m_ebpf.m_drop_failed_exit;
		break;
	case engine_kind_t::MODERN_EBPF:
		drop_failed = config->m_modern_ebpf.m_drop_failed_exit;
		break;
	default:
		drop_failed = false;
		break;
	}
	return drop_failed;
    }

    inline int16_t driver_buf_size_preset() const
    {
	int16_t index;
	switch (config->m_engine_mode) {
	case engine_kind_t::KMOD:
		index = config->m_kmod.m_buf_size_preset;
		break;
	case engine_kind_t::EBPF:
		index = config->m_ebpf.m_buf_size_preset;
		break;
	case engine_kind_t::MODERN_EBPF:
		index = config->m_modern_ebpf.m_buf_size_preset;
		break;
	default:
		// unsupported
		index = - 1;
		break;
	}
	return index;
    }
};

}; // namespace app
}; // namespace falco
