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

#include "container_engine/container_engine_base.h"
#include "logger.h"

namespace libsinsp
{

namespace container_engine
{

container_engine_base::container_engine_base(container_cache_interface &cache) :
   m_cache(cache)
{
}

void container_engine_base::update_with_size(const std::string &container_id)
{
	SINSP_DEBUG("Updating container size not supported for this container type.");
}

void container_engine_base::cleanup()
{
}

}
}
