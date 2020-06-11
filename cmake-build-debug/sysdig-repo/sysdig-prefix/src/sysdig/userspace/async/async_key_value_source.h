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
#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <thread>
#include <unordered_map>
#include <stdint.h>

namespace sysdig
{

/**
 * Base class for classes that need to collect values asynchronously from some
 * value source.  Subclasses will override the the run_impl() method and
 * implement the concrete value lookup behavior.  In that method, subclasses
 * will use use dequeue_next_key() method to get the key that it will use to
 * collect the value(s), collect the appropriate value(s), and call the
 * store_value() method to save the value.  The run_impl() method should
 * continue to dequeue and process values while the dequeue_next_key() method
 * returns true.
 *
 * The constructor for this class accepts a maximum wait time; this specifies
 * how long client code is willing to wait for a synchronous response (i.e.,
 * how long the lookup() method will block waiting for the requested value).
 * If the async_key_value_source is able to collect the requested value
 * within that time period, then the lookup() method will return them.
 *
 * If the lookup() method is unable to collect the requested value within
 * the requested time period, then one of two things will happen.
 *
 * <ol>
 * <li>If the client supplied a callback handler in the call to lookup(), then
 *     that callback handler will be invoked by the async_key_value_source once
 *     the value has been collected.  Note that the callback handler will be
 *     invoked in the context of the asynchronous thread associated with the
 *     async_key_value_source.</li>
 * <li>If the client did not supply a handler, then the value will be stored,
 *     and the next call to the lookup() method with the same key will return
 *     the previously collected value.  If lookup() is not called with the
 *     specified ttl time, then this component will prune the stored value.</li>
 * </ol>
 *
 * @tparam key_type   The type of the keys for which concrete subclasses will
 *                    query.  This type must have a valid operator==().
 * @tparam value_type The type of value that concrete subclasses will
 *                    receive from a query.  This type must have a valid
 *                    operator=().
 */
template<typename key_type, typename value_type>
class async_key_value_source
{
public:
	/**
	 * If provided to the constructor as max_wait_ms, then lookup will
	 * not wait for a response.
	 */
	const static uint64_t NO_WAIT_LOOKUP = 0;

	/**
	 * A callback handler will take a key and a output reference to the
	 * value.
	 */
        typedef std::function<void(const key_type& key,
			           const value_type& value)> callback_handler;

	/**
	 * Initialize this new async_key_value_source, which will block
	 * synchronously for the given max_wait_ms for value collection.
	 *
	 * @param[in] max_wait_ms The maximum amount of time that client code
	 *                        is willing to wait for lookup() to collect
	 *                        a value before falling back to an async
	 *                        return.
	 * @param[in] ttl_ms      The time, in milliseconds, that a cached
	 *                        value will live before being considered
	 *                        "too old" and being pruned.
	 */
	async_key_value_source(uint64_t max_wait_ms, uint64_t ttl_ms) noexcept;

	async_key_value_source(const async_key_value_source&) = delete;
	async_key_value_source(async_key_value_source&&) = delete;
	async_key_value_source& operator=(const async_key_value_source&) = delete;

	virtual ~async_key_value_source();

	/**
	 * Returns the maximum amount of time, in milliseconds, that a call to
	 * lookup() will block synchronously before returning.
	 */
	uint64_t get_max_wait() const;

	/**
	 * Returns the maximum amount of time, in milliseconds, that a cached
	 * value will live before being pruned.
	 */
	uint64_t get_ttl() const;

	/**
	 * Lookup value(s) based on the given key.  This method will block
	 * the caller for up the max_wait_ms time specified at construction
	 * for the desired value(s) to be available.
	 *
	 * @param[in] key       The key to the value for which the client
	 *                      wishes to query.
	 * @param[out] value    If this method is able to fetch the desired
	 *                      value within the max_wait_ms specified at
	 *                      construction time, then this output parameter
	 *                      will contain the collected value.  The value
	 *                      of this parameter is defined only if this method
	 *                      returns true.
	 * @param[in] handler   If this method is unable to collect the requested
	 *                      value(s) before the timeout, and if this parameter
	 *                      is a valid, non-empty, function, then this class
	 *                      will invoke the given handler from the async
	 *                      thread immediately after the collected values
	 *                      are available.  If this handler is empty, then
	 *                      this async_key_value_source will store the
	 *                      values until either the next call to lookup()
	 *                      or until its ttl expires, whichever comes first.
	 *                      The handler is responsible for any thread-safety
	 *                      guarantees.
	 *
	 * @returns true if this method was able to lookup and return the
	 *          value synchronously; false otherwise.
	 */
	bool lookup(const key_type& key,
		    value_type& value,
		    const callback_handler& handler = callback_handler());

	/**
	 * Lookup a value based on the specified key, after an initial delay.
	 * This method behaves identically to `lookup()`, except that the request
	 * is dispatched `delay` milliseconds after the call.
	 *
	 * @see lookup() for details
	 */
	bool lookup_delayed(const key_type& key,
                    value_type& value,
                    std::chrono::milliseconds delay,
                    const callback_handler& handler = callback_handler());

	/**
	 * Determines if the async thread associated with this
	 * async_key_value_source is running.
	 *
	 * <b>Note:</b> This API is for information only.  Clients should
	 * not use this to implement any sort of complex behavior.  Such
	 * use will lead to race conditions.  For example, is_running() and
	 * lookup() could potentially race, causing is_running() to return
	 * false after lookup() has started the thread.
	 *
	 * @returns true if the async thread is running, false otherwise.
	 */
	bool is_running() const;

	/**
	 * Return all results available so far
	 *
	 * All available results are moved from the internal map to the returned map
	 * so subsequent `lookup()` and/or `get_complete_results()` calls won't
	 * return them again.
	 *
	 * Sometimes there's no good place to call `lookup()` again
	 * on the async data source -- e.g. the container detection engine
	 * may never be called again for a particular container (if the only
	 * process in that container never calls `execve()` or `chroot()`
	 * or `clone()`).
	 *
	 * The best solution in that case is to supply a callback to be ran
	 * from the async lookup, but that introduces thread safety issues
	 * to the involved data.
	 *
	 * `get_complete_results()` allows batch processing of lookup results
	 * in the main thread.
	 *
	 * @return a map of lookup key -> result
	 */
	std::unordered_map<key_type, value_type> get_complete_results();

protected:
	/**
	 * Stops the thread associated with this async_key_value_source, if
	 * it is running; otherwise, does nothing.  The only use for this is
	 * in a destructor to ensure that the async thread stops when the
	 * object is destroyed.
	 */
	void stop();

	/**
	 * Dequeues an entry from the request queue and returns it in the given
	 * key.  Concrete subclasses will call this method to get the next key
	 * for which to collect values.
	 *
	 * @returns true if there was a key to dequeue, false otherwise.
	 */
	bool dequeue_next_key(key_type& key);

	/**
	 * Get the (potentially partial) value for the given key.
	 *
	 * @param[in] key The key whose value is needed.
	 *
	 * @returns the value associated with the given key.
	 */
	value_type get_value(const key_type& key);

	/**
	 * Stores a value for the given key.  Concrete subclasses will call
	 * this method from their run_impl() method to save (or otherwise
	 * notify the client about) an available value.
	 *
	 * @param[in] key   The key for which the client asked for the value.
	 * @param[in] value The collected value.
	 */
	void store_value(const key_type& key, const value_type& value);

	/**
	 * Concrete subclasses must override this method to perform the
	 * asynchronous value lookup.  The implementation should:
	 *
	 * <ul>
	 * <li>Loop while dequeue_next_key() is true.</li>
	 * <li>Get any existing value for that key using get_value()</li>
	 * <li>Do whatever work is necessary to lookup the value associated
	 *     with that key.</li>
	 * <li>Call store_value to store the updated value, and to
	 *     notify any client code waiting on that data.</li>
	 * </ul>
	 */
	virtual void run_impl() = 0;

	/**
	 * Determine the time to wait for the next request
	 *
	 * @return the absolute time until which run() may block while waiting
	 * for an incoming request
	 */
	std::chrono::steady_clock::time_point get_deadline() const;

private:
	/**
	 * Holds information associated with a single lookup() request.
	 */
	struct lookup_request
	{
		lookup_request():
			m_available(false),
			m_value(),
			m_available_condition(),
			m_callback(),
			m_start_time(std::chrono::steady_clock::now())
		{ }

		lookup_request(const lookup_request& rhs) :
		   m_available(rhs.m_available),
		   m_value(rhs.m_value),
		   m_available_condition(/*not rhs*/),
		   m_callback(rhs.m_callback),
		   m_start_time(rhs.m_start_time)
		{ }

		/** Is the value here available? */
		bool m_available;

		/** The value for a key. */
		value_type m_value;

		/** Block in lookup() waiting for a sync response. */
		std::condition_variable m_available_condition;

		/**
		 * A optional client-specified callback handler for async
		 * response notification.
		 */
		callback_handler m_callback;

		/** The time at which this request was made. */
		std::chrono::time_point<std::chrono::steady_clock> m_start_time;
	};

	typedef std::map<const key_type, lookup_request> value_map;

	/**
	 * The entry point of the async thread, which blocks waiting for work
	 * and dispatches work to run_impl().
	 */
	void run();

	/**
	 * Remove any entries that are older than the time-to-live.
	 */
	void prune_stale_requests();

	uint64_t m_max_wait_ms;
	uint64_t m_ttl_ms;
	std::thread m_thread;
	bool m_running;
	bool m_terminate;

	/**
	 * Protects the state of instances of this class.  This protected does
	 * not extend to subclasses (i.e., this mutex should not be held when
	 * dispatching to overridden methods).
	 */
	mutable std::mutex m_mutex;

	/**
	 * Enables run() to block waiting for the m_request_queue to become
	 * non-empty.
	 */
	std::condition_variable m_queue_not_empty_condition;

	using queue_item_t = std::pair<std::chrono::time_point<std::chrono::steady_clock>, key_type>;
	std::priority_queue<queue_item_t, std::vector<queue_item_t>, std::greater<queue_item_t>> m_request_queue;
	std::set<key_type> m_request_set;
	value_map m_value_map;
};


} // end namespace sysdig

#include "async_key_value_source.tpp"
