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

TEST(FalcoUtils, parse_prometheus_interval)
{
	/* Test matrix around correct time conversions. */
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1ms"), 1UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1s"), 1000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1m"), 60000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1h"), 3600000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1d"), 86400000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1w"), 604800000UL);	
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1y"), (unsigned long)31536000000UL);

	ASSERT_EQ(falco::utils::parse_prometheus_interval("300ms"), 300UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("255s"), 255000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("5m"), 300000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("15m"), 900000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("30m"), 1800000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("60m"), 3600000UL);

	/* Test matrix for concatenated time interval examples. */
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1h3m2s1ms"), 3600000UL + 3 * 60000UL + 2 * 1000UL + 1UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1y1w1d1h1m1s1ms"),(unsigned long) 31536000000UL + 604800000UL + 86400000UL + 3600000UL + 60000UL + 1000UL + 1UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("2h5m"), 2 * 3600000UL + 5 * 60000UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("2h 5m"), 2 * 3600000UL + 5 * 60000UL);

	ASSERT_EQ(falco::utils::parse_prometheus_interval("200"), 200UL);

	/* Invalid, non prometheus compliant time ordering will result in 0ms. */
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1ms1y"), 0UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1t1y"), 0UL);
	ASSERT_EQ(falco::utils::parse_prometheus_interval("1t"), 0UL);
}
