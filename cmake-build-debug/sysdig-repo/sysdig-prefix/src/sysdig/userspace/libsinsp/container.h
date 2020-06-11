/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

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

#include <functional>
#include <memory>
#include <unordered_map>

#include "scap.h"

#include "event.h"
#include "container_info.h"

#if !defined(_WIN32) && !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#endif

#include "container_engine/container_cache_interface.h"
#include "container_engine/container_engine_base.h"
#include "container_engine/sinsp_container_type.h"
#include "mutex.h"

class sinsp_container_manager :
	public libsinsp::container_engine::container_cache_interface
{
public:
	using map_ptr_t = libsinsp::ConstMutexGuard<std::unordered_map<std::string, sinsp_container_info::ptr_t>>;

	sinsp_container_manager(sinsp* inspector);
	virtual ~sinsp_container_manager();

	/**
	 * @brief Get the whole container map (read-only)
	 * @return the map of container_id -> shared_ptr<container_info>
	 */
	map_ptr_t get_containers() const;
	bool remove_inactive_containers();

	/**
	 * @brief Add/update a container in the manager map, executing on_new_container callbacks
	 *
	 * @param container_info shared_ptr owning the container_info to add/update
	 * @param thread a thread in the container, only passed to callbacks
	 */
	void add_container(const sinsp_container_info::ptr_t& container_info, sinsp_threadinfo *thread) override;

	/**
	 * @brief Update a container by replacing its entry with a new one
	 *
	 * Does not call on_new_container callbacks
	 *
	 * @param container_info shared_ptr owning the updated container_info
	 */
	void replace_container(const sinsp_container_info::ptr_t& container_info) override;

	/**
	 * @brief Get a container_info by container id
	 * @param id the id of the container to look up
	 * @return a const pointer to the container_info
	 *
	 * Note: you cannot modify the returned object in any way, to update
	 * the container, get a new shared_ptr<sinsp_container_info> and pass it
	 * to replace_container()
	 */
	sinsp_container_info::ptr_t get_container(const std::string &id) const override;

	/**
	 * @brief Generate container JSON event from a new container
	 * @param container_info reference to the new sinsp_container_info
	 *
	 * Note: this is unrelated to on_new_container callbacks even though
	 * both happen during container creation
	 */
	void notify_new_container(const sinsp_container_info& container_info) override;

	/**
	 * @brief Detect container engine for a thread
	 * @param tinfo the thread to do container detection for
	 * @param query_os_for_missing_info should we consult external data sources?
	 * 		if true, we're working with a live capture and should
	 * 		query the OS (external files, daemons etc.); if false,
	 * 		we're reading a scap file so only rely on the thread info itself
	 * @return true if we have successfully determined the container engine,
	 * 		false otherwise
	 *
	 * Note: a return value of false doesn't mean that container detection failed,
	 * it may still be happening in the background asynchronously
	 */
	bool resolve_container(sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	void dump_containers(scap_dumper_t* dumper);
	std::string get_container_name(sinsp_threadinfo* tinfo) const;

	// Set tinfo's m_category based on the container context.  It
	// will *not* change any category to NONE, so a threadinfo
	// that initially has a category will retain its category
	// across execs e.g. "sh -c /bin/true" execing /bin/true.
	void identify_category(sinsp_threadinfo *tinfo);

	bool container_exists(const std::string& container_id) const override{
		auto containers = m_containers.lock();
		return containers->find(container_id) != containers->end() ||
			m_lookups.find(container_id) != m_lookups.end();
	}

	typedef std::function<void(const sinsp_container_info&, sinsp_threadinfo *)> new_container_cb;
	typedef std::function<void(const sinsp_container_info&)> remove_container_cb;
	void subscribe_on_new_container(new_container_cb callback);
	void subscribe_on_remove_container(remove_container_cb callback);

	void create_engines();

	/**
	 * Update the container_info associated with the given type and container_id
	 * to include the size of the container layer. This is not filled in the
	 * initial request because it can easily take seconds.
	 */
	void update_container_with_size(sinsp_container_type type,
					const std::string& container_id);
	void cleanup();

	void set_docker_socket_path(std::string socket_path);
	void set_query_docker_image_info(bool query_image_info);
	void set_cri_extra_queries(bool extra_queries);
	void set_cri_socket_path(const std::string& path);
	void set_cri_timeout(int64_t timeout_ms);
	void set_cri_async(bool async);
	void set_cri_delay(uint64_t delay_ms);
	sinsp* get_inspector() { return m_inspector; }

	/**
	 * \brief set the status of an async container metadata lookup
	 * @param container_id the container id we're looking up
	 * @param ctype the container engine that is doing the lookup
	 * @param state the state of the lookup
	 *
	 * Container engines that do not do any lookups in external services need not
	 * bother with this. Otherwise, the engine needs to maintain the current
	 * state of the lookup via this method and call should_lookup() before
	 * starting a new lookup.
	 */
	void set_lookup_status(const std::string& container_id, sinsp_container_type ctype, sinsp_container_lookup_state state) override
	{
		m_lookups[container_id][ctype] = state;
	}

	/**
	 * \brief do we want to start a new lookup for container metadata?
	 * @param container_id the container id we want to look up
	 * @param ctype the container engine that is doing the lookup
	 * @return true if there's no lookup in progress and we're free to start
	 * a new one, false otherwise
	 *
	 * This method effectively checks if m_lookups[container_id][ctype]
	 * exists, without creating unnecessary map entries along the way.
	 */
	bool should_lookup(const std::string& container_id, sinsp_container_type ctype) override
	{
		auto container_lookups = m_lookups.find(container_id);
		if(container_lookups == m_lookups.end())
		{
			return true;
		}
		auto engine_lookup = container_lookups->second.find(ctype);
		return engine_lookup == container_lookups->second.end();
	}
private:
	std::string container_to_json(const sinsp_container_info& container_info);
	bool container_to_sinsp_event(const std::string& json, sinsp_evt* evt, std::shared_ptr<sinsp_threadinfo> tinfo);
	std::string get_docker_env(const Json::Value &env_vars, const std::string &mti);

	std::list<std::shared_ptr<libsinsp::container_engine::container_engine_base>> m_container_engines;
	std::map<sinsp_container_type, std::shared_ptr<libsinsp::container_engine::container_engine_base>> m_container_engine_by_type;

	sinsp* m_inspector;
	libsinsp::Mutex<std::unordered_map<std::string, std::shared_ptr<const sinsp_container_info>>> m_containers;
	std::unordered_map<std::string, std::unordered_map<sinsp_container_type, sinsp_container_lookup_state>> m_lookups;
	uint64_t m_last_flush_time_ns;
	std::list<new_container_cb> m_new_callbacks;
	std::list<remove_container_cb> m_remove_callbacks;

	friend class test_helper;
};

