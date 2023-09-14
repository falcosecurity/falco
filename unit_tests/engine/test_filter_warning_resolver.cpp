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

#include <gtest/gtest.h>
#include <engine/filter_warning_resolver.h>

static bool warns(const std::string& condition)
{
	std::set<falco::load_result::warning_code> w;
	auto ast = libsinsp::filter::parser(condition).parse();
	filter_warning_resolver().run(ast.get(), w);
	return !w.empty();
}

TEST(WarningResolver, warnings_in_filtering_conditions)
{
	ASSERT_FALSE(warns("ka.field exists"));
	ASSERT_FALSE(warns("some.field = <NA>"));
	ASSERT_TRUE(warns("jevt.field = <NA>"));
	ASSERT_TRUE(warns("ka.field = <NA>"));
	ASSERT_TRUE(warns("ka.field == <NA>"));
	ASSERT_TRUE(warns("ka.field != <NA>"));
	ASSERT_TRUE(warns("ka.field in (<NA>)"));
	ASSERT_TRUE(warns("ka.field in (otherval, <NA>)"));
	ASSERT_TRUE(warns("ka.field intersects (<NA>)"));
	ASSERT_TRUE(warns("ka.field intersects (otherval, <NA>)"));
	ASSERT_TRUE(warns("ka.field pmatch (<NA>)"));
	ASSERT_TRUE(warns("ka.field pmatch (otherval, <NA>)"));
}
