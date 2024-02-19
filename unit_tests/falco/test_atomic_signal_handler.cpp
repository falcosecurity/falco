// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless ASSERTd by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <falco/atomic_signal_handler.h>
#include <falco/logger.h>

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <vector>

TEST(AtomicSignalHandler, lock_free_implementation)
{
	ASSERT_TRUE(falco::atomic_signal_handler().is_lock_free());
}

TEST(AtomicSignalHandler, handle_once_wait_consistency)
{
	constexpr const auto thread_num = 10;
	constexpr const std::chrono::seconds thread_wait_sec{2};
	constexpr const std::chrono::seconds handler_wait_sec{1};

	// have a shared signal handler
	falco::atomic_signal_handler handler;

	// launch a bunch of threads all syncing on the same handler
	struct task_result_t
	{
		bool handled;
		std::chrono::seconds duration_secs;
	};

	std::vector<std::future<task_result_t>> futures;
	for (int i = 0; i < thread_num; i++)
	{
		futures.emplace_back(std::async(std::launch::async,
			[&handler, thread_wait_sec]() {
				auto start = std::chrono::high_resolution_clock::now();
				task_result_t res;
				res.handled = false;
				while (!handler.handled())
				{
					if (handler.triggered())
					{
						res.handled = handler.handle([thread_wait_sec]() {
							std::this_thread::sleep_for(thread_wait_sec);
						});
					}
				}
				auto diff = std::chrono::high_resolution_clock::now() - start;
				res.duration_secs = std::chrono::duration_cast<std::chrono::seconds>(diff);
				return res;
			}));
	}

	// wait a bit, then trigger the signal handler from the main thread
	auto total_handled = 0;
	auto start = std::chrono::high_resolution_clock::now();
	std::this_thread::sleep_for(handler_wait_sec);
	handler.trigger();
	for (int i = 0; i < thread_num; i++)
	{
		// wait for all threads to finish and get the results from the futures
		auto res = futures[i].get();
		if (res.handled)
		{
			total_handled++;
		}
		ASSERT_GE(res.duration_secs, thread_wait_sec);
	}

	// check that the total time is consistent with the expectations
	auto diff = std::chrono::high_resolution_clock::now() - start;
	auto secs = std::chrono::duration_cast<std::chrono::seconds>(diff);
	ASSERT_GE(secs, thread_wait_sec + handler_wait_sec);

	// check that only one thread handled the signal
	ASSERT_EQ(total_handled, 1);
}

TEST(AtomicSignalHandler, handle_and_reset)
{
	auto do_nothing = []{};
	falco::atomic_signal_handler handler;

	ASSERT_FALSE(handler.triggered());
	ASSERT_FALSE(handler.handled());
	ASSERT_FALSE(handler.handle(do_nothing));

	handler.trigger();
	ASSERT_TRUE(handler.triggered());
	ASSERT_FALSE(handler.handled());

	ASSERT_TRUE(handler.handle(do_nothing));
	ASSERT_TRUE(handler.triggered());
	ASSERT_TRUE(handler.handled());
	ASSERT_FALSE(handler.handle(do_nothing));

	handler.trigger();
	ASSERT_TRUE(handler.triggered());
	ASSERT_FALSE(handler.handled());
	ASSERT_TRUE(handler.handle(do_nothing));
	ASSERT_TRUE(handler.triggered());
	ASSERT_TRUE(handler.handled());
	ASSERT_FALSE(handler.handle(do_nothing));

	handler.reset();
	ASSERT_FALSE(handler.triggered());
	ASSERT_FALSE(handler.handled());
	ASSERT_FALSE(handler.handle(do_nothing));
}
