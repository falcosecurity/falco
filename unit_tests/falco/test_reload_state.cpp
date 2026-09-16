// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <falco/app/reload_state.h>

#include <gtest/gtest.h>

TEST(ReloadState, signal_requests_are_lock_free) {
	falco::app::reload_state state;
	EXPECT_TRUE(state.is_lock_free());
}

TEST(ReloadState, rejected_validation_covers_checked_requests) {
	falco::app::reload_state state;
	state.begin_run();

	state.request();
	state.request();
	const auto attempt = state.begin_check();
	EXPECT_EQ(state.covered(), 0);
	ASSERT_EQ(attempt.requests, 2);

	state.rejected(attempt);
	EXPECT_EQ(state.covered(), attempt.requests);
	EXPECT_EQ(state.covered(), state.requested());
}

TEST(ReloadState, request_arriving_during_rejected_validation_remains_pending) {
	falco::app::reload_state state;
	state.request();
	const auto attempt = state.begin_check();
	state.request();
	state.rejected(attempt);

	EXPECT_EQ(state.covered(), attempt.requests);
	EXPECT_GT(state.requested(), state.covered());

	const auto retry = state.begin_check();
	EXPECT_EQ(retry.requests, state.requested());
	state.rejected(retry);
	EXPECT_EQ(state.covered(), state.requested());
}

TEST(ReloadState, run_captures_only_requests_received_before_configuration_read) {
	falco::app::reload_state state;
	state.request();
	const auto before_read = state.requested();
	state.begin_run();
	EXPECT_EQ(state.covered(), before_read);

	// A subsequent write and signal must survive completion of this run.
	state.request();
	EXPECT_EQ(state.covered(), before_read);
	EXPECT_GT(state.requested(), state.covered());

	state.begin_run();
	EXPECT_EQ(state.covered(), state.requested());
}

TEST(ReloadState, requests_survive_the_gap_between_runtime_instances) {
	falco::app::reload_state state;
	state.begin_run();
	state.request();
	const auto accepted_check = state.begin_check();

	// Model the retiring restart worker completing validation and stopping.
	state.request();
	const auto during_teardown = state.requested();
	ASSERT_GT(during_teardown, accepted_check.requests);
	EXPECT_EQ(state.requested(), during_teardown);
	EXPECT_LT(state.covered(), during_teardown);

	// The replacement captures the request before it reads configuration.
	state.begin_run();
	EXPECT_EQ(state.covered(), during_teardown);
}
