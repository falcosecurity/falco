/*
Copyright (C) 2020 The Falco Authors.

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

#include <chrono>
#include <thread>
#include <functional>
#include <atomic>

template<typename _T>
class watchdog
{
public:
	watchdog():
		m_timeout(nullptr),
		m_is_running(false)
	{
	}

	~watchdog()
	{
		stop();
	}

	void start(std::function<void(_T)> cb,
		   std::chrono::milliseconds resolution = std::chrono::milliseconds(100))
	{
		stop();
		m_is_running.store(true, std::memory_order_release);
		m_thread = std::thread([this, cb, resolution]() {
			const auto no_deadline = time_point{};
			timeout_data curr;
			while(m_is_running.load(std::memory_order_acquire))
			{
				auto t = m_timeout.exchange(nullptr, std::memory_order_release);
				if(t)
				{
					curr = *t;
					delete t;
				}
				if(curr.deadline != no_deadline && curr.deadline < std::chrono::steady_clock::now())
				{
					cb(curr.payload);
					curr.deadline = no_deadline;
				}
				std::this_thread::sleep_for(resolution);
			}
		});
	}

	void stop()
	{
		if(m_is_running.load(std::memory_order_acquire))
		{
			m_is_running.store(false, std::memory_order_release);
			if(m_thread.joinable())
			{
				m_thread.join();
			}
			delete m_timeout.exchange(nullptr, std::memory_order_release);
		}
	}

	inline void set_timeout(std::chrono::milliseconds timeout, _T payload) noexcept
	{
		delete m_timeout.exchange(new timeout_data{std::chrono::steady_clock::now() + timeout, payload}, std::memory_order_release);
	}

	inline void cancel_timeout() noexcept
	{
		delete m_timeout.exchange(new timeout_data, std::memory_order_release);
	}

private:
	typedef std::chrono::time_point<std::chrono::steady_clock> time_point;
	struct timeout_data
	{
		time_point deadline;
		_T payload;
	};
	std::atomic<timeout_data *> m_timeout;
	std::atomic<bool> m_is_running;
	std::thread m_thread;
};