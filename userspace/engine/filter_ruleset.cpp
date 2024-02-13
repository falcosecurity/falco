// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include "filter_ruleset.h"

void filter_ruleset::set_engine_state(const filter_ruleset::engine_state_funcs& engine_state)
{
	m_engine_state = engine_state;
}

filter_ruleset::engine_state_funcs& filter_ruleset::get_engine_state()
{
	return m_engine_state;
}
