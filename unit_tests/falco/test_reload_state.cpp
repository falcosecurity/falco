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

TEST(ReloadState, applies_only_after_all_expected_sources_start) {
	falco::app::reload_state state;
	state.begin_run();
	state.expect_sources(3);
	const auto generation = state.get().started_generation;
	ASSERT_GT(generation, 0);

	for(int i = 0; i < 2; ++i) {
		state.source_started();
		EXPECT_FALSE(state.get().ready);
		EXPECT_EQ(state.get().applied_generation, 0);
	}

	state.source_started();
	EXPECT_TRUE(state.get().ready);
	EXPECT_EQ(state.get().applied_generation, generation);
}

TEST(ReloadState, stopped_run_cannot_become_ready_when_remaining_source_starts) {
	falco::app::reload_state state;
	state.begin_run();
	state.expect_sources(1);
	state.source_started();
	const auto applied = state.get().applied_generation;
	ASSERT_TRUE(state.get().ready);

	state.begin_run();
	state.expect_sources(2);
	state.source_started();
	state.stop();
	// A remaining source may report startup after another source has failed.
	state.source_started();
	EXPECT_FALSE(state.get().ready);
	EXPECT_EQ(state.get().applied_generation, applied);

	state.begin_run();
	state.expect_sources(1);
	state.source_started();
	EXPECT_TRUE(state.get().ready);
	EXPECT_EQ(state.get().applied_generation, state.get().started_generation);
	EXPECT_GT(state.get().applied_generation, applied);
}

TEST(ReloadState, rejecting_validation_preserves_the_applied_runtime) {
	falco::app::reload_state state;
	state.begin_run();
	state.expect_sources(1);
	state.source_started();
	const auto applied = state.get().applied_generation;

	state.request();
	state.request();
	const auto attempt = state.begin_check();
	EXPECT_TRUE(state.get().ready);
	EXPECT_EQ(state.get().applied_generation, applied);
	EXPECT_EQ(state.covered(), 0);
	ASSERT_EQ(attempt.requests, 2);

	state.rejected(attempt);
	EXPECT_TRUE(state.get().ready);
	EXPECT_EQ(state.get().applied_generation, applied);
	EXPECT_EQ(state.get().rejected_generation, attempt.generation);
	EXPECT_GT(attempt.generation, applied);
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
	EXPECT_EQ(state.get().rejected_generation, attempt.generation);
	EXPECT_EQ(state.get().applied_generation, 0);
	EXPECT_FALSE(state.get().ready);

	const auto retry = state.begin_check();
	EXPECT_GT(retry.generation, attempt.generation);
	EXPECT_EQ(retry.requests, state.requested());
	state.rejected(retry);
	EXPECT_EQ(state.covered(), state.requested());
	EXPECT_EQ(state.get().rejected_generation, retry.generation);
}

TEST(ReloadState, run_captures_only_requests_received_before_configuration_read) {
	falco::app::reload_state state;
	state.request();
	const auto before_read = state.requested();
	state.begin_run();
	state.expect_sources(1);
	EXPECT_EQ(state.covered(), before_read);
	EXPECT_EQ(state.get().applied_generation, 0);
	EXPECT_FALSE(state.get().ready);

	// A subsequent write and signal must survive completion of this run.
	state.request();
	state.source_started();
	EXPECT_TRUE(state.get().ready);
	EXPECT_EQ(state.covered(), before_read);
	EXPECT_GT(state.requested(), state.covered());

	state.stop();
	EXPECT_GT(state.requested(), state.covered());
	state.begin_run();
	EXPECT_EQ(state.covered(), state.requested());
	EXPECT_FALSE(state.get().ready);
}

TEST(ReloadState, requests_survive_the_gap_between_runtime_instances) {
	falco::app::reload_state state;
	state.begin_run();
	state.expect_sources(1);
	state.source_started();
	state.request();
	const auto accepted_check = state.begin_check();

	// Model the retiring restart worker completing validation and stopping.
	state.stop();
	state.request();
	const auto during_teardown = state.requested();
	ASSERT_GT(during_teardown, accepted_check.requests);
	state.stop();
	EXPECT_EQ(state.requested(), during_teardown);
	EXPECT_LT(state.covered(), during_teardown);

	// The replacement captures the request before it reads configuration.
	state.begin_run();
	EXPECT_EQ(state.covered(), during_teardown);
	EXPECT_FALSE(state.get().ready);
	state.expect_sources(1);
	state.source_started();
	EXPECT_TRUE(state.get().ready);
	EXPECT_EQ(state.get().applied_generation, state.get().started_generation);
}

TEST(ReloadState, completing_a_run_started_before_baseline_does_not_confirm_a_later_write) {
	falco::app::reload_state state;
	state.begin_run();
	state.expect_sources(1);
	const auto baseline = state.get().started_generation;
	state.request();
	state.source_started();

	EXPECT_TRUE(state.get().ready);
	EXPECT_EQ(state.get().applied_generation, baseline);
	EXPECT_FALSE(state.get().applied_generation > baseline);
	EXPECT_GT(state.requested(), state.covered());

	state.stop();
	state.begin_run();
	state.expect_sources(1);
	state.source_started();
	EXPECT_GT(state.get().applied_generation, baseline);
}

TEST(ReloadState, rejecting_a_check_started_before_baseline_does_not_reject_a_later_write) {
	falco::app::reload_state state;
	state.request();
	const auto attempt = state.begin_check();
	const auto baseline = state.get().started_generation;
	state.request();
	state.rejected(attempt);

	EXPECT_EQ(state.get().rejected_generation, baseline);
	EXPECT_FALSE(state.get().rejected_generation > baseline);
	EXPECT_GT(state.requested(), state.covered());

	const auto retry = state.begin_check();
	state.rejected(retry);
	EXPECT_GT(state.get().rejected_generation, baseline);
	EXPECT_EQ(state.covered(), state.requested());
}

TEST(ReloadState, process_identity_is_initialized_once_and_survives_runtime_replacement) {
	falco::app::reload_state first_process;
	falco::app::reload_state second_process;
	first_process.initialize();
	second_process.initialize();
	const auto first_id = first_process.get().instance_id;
	const auto second_id = second_process.get().instance_id;
	ASSERT_FALSE(first_id.empty());
	ASSERT_FALSE(second_id.empty());
	EXPECT_NE(first_id, second_id);

	for(int i = 0; i < 2; ++i) {
		first_process.initialize();
		first_process.begin_run();
		first_process.expect_sources(1);
		first_process.source_started();
		first_process.stop();
		EXPECT_EQ(first_process.get().instance_id, first_id);
		EXPECT_EQ(second_process.get().instance_id, second_id);
	}
}

TEST(ReloadState, observations_do_not_consume_requests_or_advance_generations) {
	falco::app::reload_state state;
	state.initialize();
	state.begin_run();
	state.expect_sources(1);
	state.source_started();
	state.request();
	const auto rejected = state.begin_check();
	state.rejected(rejected);
	state.request();
	const auto before = state.get();
	const auto requested = state.requested();
	const auto covered = state.covered();
	ASSERT_GT(requested, covered);

	for(int i = 0; i < 3; ++i) {
		const auto observed = state.get();
		EXPECT_EQ(observed.instance_id, before.instance_id);
		EXPECT_EQ(observed.started_generation, before.started_generation);
		EXPECT_EQ(observed.applied_generation, before.applied_generation);
		EXPECT_EQ(observed.rejected_generation, before.rejected_generation);
		EXPECT_EQ(observed.ready, before.ready);
		EXPECT_EQ(state.requested(), requested);
		EXPECT_EQ(state.covered(), covered);
	}
}
