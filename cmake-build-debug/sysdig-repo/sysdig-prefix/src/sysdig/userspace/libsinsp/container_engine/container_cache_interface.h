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

#include "container_info.h"

namespace libsinsp
{
namespace container_engine
{

/**
 * Interface for a container cache for container engines.
 */
class container_cache_interface
{
public:
	virtual ~container_cache_interface() = default;

	virtual void notify_new_container(const sinsp_container_info& container_info) = 0;

	virtual bool should_lookup(const std::string& container_id, sinsp_container_type ctype) = 0;

	virtual void set_lookup_status(const std::string& container_id, sinsp_container_type ctype, sinsp_container_lookup_state state) = 0;

	/**
	 * Get a container from the cache.
	 */
	virtual sinsp_container_info::ptr_t get_container(const std::string& id) const = 0;

	/**
	 * Add a new container to the cache.
	 */
	virtual void add_container(const sinsp_container_info::ptr_t& container_info, sinsp_threadinfo *thread) = 0;

	/**
	 * Update a container by replacing its entry with a new one
	 */
	virtual void replace_container(const sinsp_container_info::ptr_t& container_info) = 0;

	/**
	 * Return whether the container exists in the cache.
	 */
	virtual bool container_exists(const std::string& container_id) const = 0;
};

}
}
