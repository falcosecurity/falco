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

#include "sinsp.h"
#include "sinsp_int.h"

#ifdef GATHER_INTERNAL_STATS
namespace internal_metrics
{

counter::~counter()
{
}

counter::counter()
{
	m_value = 0;
}

void registry::clear_all_metrics()
{
	for(metric_map_iterator_t it = get_metrics().begin(); it != get_metrics().end(); it++)
	{
		it->second->clear();
	}

}

}
#endif
