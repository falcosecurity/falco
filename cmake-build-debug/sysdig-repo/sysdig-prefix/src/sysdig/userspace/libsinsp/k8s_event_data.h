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
// k8s_event_data.h
//
// connects and gets the data from k8s_net REST API interface
//
#pragma once

#include "k8s_component.h"


class k8s_event_data
{
public:
	k8s_event_data() = delete;

	k8s_event_data(k8s_component::type component, const char* data, int len);

	k8s_event_data(const k8s_event_data& other);

	k8s_event_data(k8s_event_data&& other);

	k8s_event_data& operator=(k8s_event_data&& other);

	k8s_component::type component() const;

	std::string data() const;

private:
	k8s_component::type m_component;
	std::string         m_data;
};

inline k8s_component::type k8s_event_data::component() const
{
	return m_component;
}
	
inline std::string k8s_event_data::data() const
{
	return m_data;
}