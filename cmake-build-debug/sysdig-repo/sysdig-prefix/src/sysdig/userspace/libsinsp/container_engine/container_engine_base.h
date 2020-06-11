/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

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

#include "container_engine/container_cache_interface.h"

class sinsp_threadinfo;

namespace libsinsp {
namespace container_engine {

/**
 * Base class for container engine. This provides the interfaces to
 * create a sinsp_container_info.
 */
class container_engine_base {
public:
	container_engine_base(container_cache_interface &cache);

	virtual ~container_engine_base() = default;

	/**
	 * Find a container associated with the given tinfo and add it to the
	 * cache.
	 */
	virtual bool resolve(sinsp_threadinfo* tinfo,
			     bool query_os_for_missing_info) = 0;

	/**
	 * Update an existing container with the size of the container layer.
	 * The size is not requested as the part of the initial request (in resolve)
	 * because determining the size can take seconds.
	 */
	virtual void update_with_size(const std::string& container_id);

	virtual void cleanup();

protected:
	/**
	 * Derived class accessor to the cache
	 */
	container_cache_interface& container_cache()
	{
		return m_cache;
	}

private:
	container_cache_interface& m_cache;
};
}
}

