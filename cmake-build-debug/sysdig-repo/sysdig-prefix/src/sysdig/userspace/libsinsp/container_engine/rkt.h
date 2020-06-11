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

#include <string>

class sinsp_container_info;
class sinsp_threadinfo;

#include "container_engine/container_engine_base.h"
#include "sinsp_container_type.h"

namespace libsinsp {
namespace container_engine {
class rkt : public container_engine_base
{
public:
	rkt(container_cache_interface& cache) : container_engine_base(cache)
	{}

	bool resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info) override;

protected:
	bool match(container_cache_interface *cache, sinsp_threadinfo *tinfo, sinsp_container_info& container_info,
		   std::string& rkt_podid, std::string& rkt_appname, bool query_os_for_missing_info);

	bool parse_rkt(sinsp_container_info& container, const std::string& podid, const std::string& appname);
};
}
}
