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
// mesos_collector.h
//

#pragma once

#ifdef HAS_CAPTURE

#include "mesos_common.h"
#include <map>
#include <memory>

class mesos_http;

class mesos_collector
{
public:
	typedef std::map<int, std::shared_ptr<mesos_http>> socket_map_t;

	mesos_collector(bool do_loop = true, long timeout_ms = 1000L);

	~mesos_collector();

	void add(std::shared_ptr<mesos_http> handler);

	void remove_all();

	int subscription_count() const;

	void get_data();

	void stop();

	bool is_active() const;
	bool is_healthy(int expected_count) const;

	bool has(std::shared_ptr<mesos_http> handler);
	bool remove(std::shared_ptr<mesos_http> handler);

private:
	void clear();
	socket_map_t::iterator& remove(socket_map_t::iterator& it);

	socket_map_t     m_sockets;
	fd_set           m_infd;
	fd_set           m_errfd;
	int              m_nfds;
	bool             m_loop;
	long             m_timeout_ms;
	bool             m_stopped;
};

inline void mesos_collector::stop()
{
	m_stopped = true;
}

#endif // HAS_CAPTURE
