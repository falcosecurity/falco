/*
Copyright (C) 2023 The Falco Authors.

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

#include <gtest/gtest.h>
#include <engine/falco_utils.h>

TEST(FalcoUtils, is_unix_scheme)
{
	/* Wrong prefix */
	ASSERT_EQ(falco::utils::network::is_unix_scheme("something:///run/falco/falco.sock"), false);

	/* Similar prefix, but wrong */
	ASSERT_EQ(falco::utils::network::is_unix_scheme("unix///falco.sock"), false);

	/* Right prefix, passed as an `rvalue` */
	ASSERT_EQ(falco::utils::network::is_unix_scheme("unix:///falco.sock"), true);

	/* Right prefix, passed as a `std::string` */
	std::string url_string("unix:///falco.sock");
	ASSERT_EQ(falco::utils::network::is_unix_scheme(url_string), true);

	/* Right prefix, passed as a `char[]` */
	char url_char[] = "unix:///falco.sock";
	ASSERT_EQ(falco::utils::network::is_unix_scheme(url_char), true);
}
