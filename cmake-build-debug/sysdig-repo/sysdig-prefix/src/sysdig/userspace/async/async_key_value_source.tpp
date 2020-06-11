/*
Copyright (C) 2019 Sysdig, Inc.

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
#include "logger.h"

#include <assert.h>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <list>
#include <string>
#include <utility>
#include <vector>

namespace sysdig
{

template<typename key_type, typename value_type>
async_key_value_source<key_type, value_type>::async_key_value_source(
		const uint64_t max_wait_ms,
		const uint64_t ttl_ms) noexcept:
	m_max_wait_ms(max_wait_ms),
	m_ttl_ms(ttl_ms),
	m_thread(),
	m_running(false),
	m_terminate(false),
	m_mutex(),
	m_queue_not_empty_condition(),
	m_value_map()
{ }

template<typename key_type, typename value_type>
async_key_value_source<key_type, value_type>::~async_key_value_source()
{
	try
	{
		stop();
	}
	catch(...)
	{
		g_logger.log(std::string(__FUNCTION__) +
		             ": Exception in destructor",
		             sinsp_logger::SEV_ERROR);
	}
}

template<typename key_type, typename value_type>
uint64_t async_key_value_source<key_type, value_type>::get_max_wait() const
{
	return m_max_wait_ms;
}

template<typename key_type, typename value_type>
uint64_t async_key_value_source<key_type, value_type>::get_ttl() const
{
	return m_ttl_ms;
}

template<typename key_type, typename value_type>
void async_key_value_source<key_type, value_type>::stop()
{
	bool join_needed = false;

	{
		std::unique_lock<std::mutex> guard(m_mutex);

		if(m_running)
		{
			m_terminate = true;
			join_needed = true;

			// The async thread might be waiting for new events
			// so wake it up
			m_queue_not_empty_condition.notify_one();
		}
	} // Drop the mutex before join()

	if (join_needed)
	{
		m_thread.join();

		// Remove any pointers from the thread to this object
		// (just to be safe)
		m_thread = std::thread();
	}
}

template<typename key_type, typename value_type>
bool async_key_value_source<key_type, value_type>::is_running() const
{
	// Since this is for information only and it's ok to race, we
	// explicitly do not lock here.

	return m_running;
}

template<typename key_type, typename value_type>
void async_key_value_source<key_type, value_type>::run()
{
	m_running = true;

	while(!m_terminate)
	{
		{
			std::unique_lock<std::mutex> guard(m_mutex);

			while(!m_terminate)
			{
				// Wait for something to show up on the queue
				auto deadline = get_deadline();
				if (deadline == std::chrono::steady_clock::time_point::min())
				{
					break;
				}
				else if (deadline == std::chrono::steady_clock::time_point::max())
				{
					// https://stackoverflow.com/questions/39041450/stdcondition-variable-wait-until-surprising-behaviour
					m_queue_not_empty_condition.wait(guard);
				}
				else
				{
					m_queue_not_empty_condition.wait_until(guard, deadline);
				}
			}

			prune_stale_requests();
		}

		if(!m_terminate)
		{

			run_impl();
		}
	}

	m_running = false;
}

template<typename key_type, typename value_type>
bool async_key_value_source<key_type, value_type>::lookup_delayed(
		const key_type& key,
		value_type& value,
		std::chrono::milliseconds delay,
		const callback_handler& handler)
{
	std::unique_lock<std::mutex> guard(m_mutex);

	if(!m_running && !m_thread.joinable())
	{
		m_thread = std::thread(&async_key_value_source::run, this);
	}

	typename value_map::iterator itr = m_value_map.find(key);
	bool request_complete;

	if (itr == m_value_map.end())
	{
		// Haven't made the request yet. Be explicit and validate insertion.
		auto insert_result = m_value_map.emplace(key, lookup_request());

		if(!insert_result.second)
		{
			g_logger.log("async_key_value_source: Failed to insert an empty item "
						 "into the container cache.", sinsp_logger::SEV_ERROR);
			return false;
		}

		// Replace the itr with the mapped value
		itr = insert_result.first;

		// Not sure why setting the value is needed, but being consistent with
		// previous implementation.
		itr->second.m_value = value;

		// Make request to API and let the async thread know about it
		if (std::find(m_request_set.begin(),
		              m_request_set.end(),
		              key) == m_request_set.end())
		{
			auto start_time = std::chrono::steady_clock::now() + delay;
			m_request_queue.push(std::make_pair(start_time, key));
			m_request_set.insert(key);
			m_queue_not_empty_condition.notify_one();
		}
		request_complete = false;
	}
	else
	{
		request_complete = itr->second.m_available;
	}

	if(!request_complete && m_max_wait_ms > 0)
	{
		//
		// If the client code is willing to wait a short amount of time
		// to satisfy the request, then wait for the async thread to
		// pick up the newly-added request and execute it.  If
		// processing that request takes too much time, then we'll
		// not be able to return the value information on this call,
		// and the async thread will continue handling the request so
		// that it'll be available on the next call.
		//
		itr->second.m_available_condition.wait_for(
				guard,
				std::chrono::milliseconds(m_max_wait_ms));

		// Replace the iterator in case something changed
		itr = m_value_map.find(key);
		request_complete = (itr != m_value_map.end()) && itr->second.m_available;
	}

	if(request_complete)
	{
		// Pass the value back the caller and erase from the list.
		value = itr->second.m_value;
		m_value_map.erase(itr);
	}
	else
	{
		// Set the callback to fill the value later
		itr->second.m_callback = handler;
	}

	return request_complete;
}

template<typename key_type, typename value_type>
bool async_key_value_source<key_type, value_type>::lookup(
	const key_type& key,
	value_type& value,
	const callback_handler& handler)
{
	return lookup_delayed(key, value, std::chrono::milliseconds::zero(), handler);
}

template<typename key_type, typename value_type>
bool async_key_value_source<key_type, value_type>::dequeue_next_key(key_type& key)
{
	std::lock_guard<std::mutex> guard(m_mutex);
	bool key_found = false;

	if(!m_request_queue.empty())
	{
		auto top_element = m_request_queue.top();
		if(top_element.first < std::chrono::steady_clock::now())
		{
			key_found = true;
			key = std::move(top_element.second);
			m_request_queue.pop();
			m_request_set.erase(key);
		}
	}

	return key_found;
}

template<typename key_type, typename value_type>
value_type async_key_value_source<key_type, value_type>::get_value(
		const key_type& key)
{
	std::lock_guard<std::mutex> guard(m_mutex);

	return m_value_map[key].m_value;
}

template<typename key_type, typename value_type>
void async_key_value_source<key_type, value_type>::store_value(
		const key_type& key,
		const value_type& value)
{
	std::lock_guard<std::mutex> guard(m_mutex);

	typename value_map::iterator itr = m_value_map.find(key);
	if(itr == m_value_map.end())
	{
		g_logger.log("async_key_value_source: Container not found when committing "
					 "to container cache. Either the container no longer exists or "
					 "the container lookup took longer than the timeout.",
					 sinsp_logger::SEV_WARNING);
		return;
	}

	if (itr->second.m_callback)
	{
		itr->second.m_callback(key, value);
		m_value_map.erase(itr);
	}
	else
	{
		itr->second.m_value = value;
		itr->second.m_available = true;
		itr->second.m_available_condition.notify_one();
	}
}

/**
 * Prune any "old" outstanding requests.  This method expects that the caller
 * is holding m_mutex.
 */
template<typename key_type, typename value_type>
void async_key_value_source<key_type, value_type>::prune_stale_requests()
{
	// Avoid both iterating over and modifying the map by saving a list
	// of keys to prune.
	std::vector<key_type> keys_to_prune;

	for(auto i = m_value_map.begin();
	    !m_terminate && (i != m_value_map.end());
	    ++i)
	{
		const auto now = std::chrono::steady_clock::now();

		const uint64_t age_ms =
			std::chrono::duration_cast<std::chrono::milliseconds>(
					now - i->second.m_start_time).count();

		if(age_ms > m_ttl_ms)
		{
			keys_to_prune.push_back(i->first);
		}
	}

	for(auto i = keys_to_prune.begin();
	    !m_terminate && (i != keys_to_prune.end());
	    ++i)
	{
		m_value_map.erase(*i);
	}
}

template<typename key_type, typename value_type>
std::unordered_map<key_type, value_type> async_key_value_source<key_type, value_type>::get_complete_results()
{
	std::unordered_map<key_type, value_type> results;

	std::lock_guard<std::mutex> guard(m_mutex);

	for(const auto& it : m_value_map)
	{
		if(it.second.m_available)
		{
			results[it.first] = it.second.m_value;
		}
	}

	for(const auto& it : results)
	{
		m_value_map.erase(it.first);
	}

	return results;
}

// called with m_mutex held
template<typename key_type, typename value_type>
std::chrono::steady_clock::time_point async_key_value_source<key_type, value_type>::get_deadline() const
{
	if (m_request_queue.empty())
	{
		return std::chrono::steady_clock::time_point::max();
	}

	auto next_request = m_request_queue.top();
	if (next_request.first <= std::chrono::steady_clock::now())
	{
		return std::chrono::steady_clock::time_point::min();
	}

	return next_request.first;
}

} // end namespace sysdig

