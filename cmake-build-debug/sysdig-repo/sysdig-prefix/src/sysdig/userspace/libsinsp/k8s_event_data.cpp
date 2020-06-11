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
//
// k8s_net.cpp
//


#include "k8s_event_data.h"

k8s_event_data::k8s_event_data(k8s_component::type component, const char* data, int len):
	m_component(component),
	m_data(data, len)
{
}

k8s_event_data::k8s_event_data(const k8s_event_data& other):
	m_component(other.m_component),
	m_data(other.m_data)
{
}

k8s_event_data::k8s_event_data(k8s_event_data&& other):
	m_component(std::move(other.m_component)),
	m_data(std::move(other.m_data))
{
}

k8s_event_data& k8s_event_data::operator=(k8s_event_data&& other)
{
	if(this != &other)
	{
		m_component = other.m_component;
		m_data = other.m_data;
	}
	return *this;
}
