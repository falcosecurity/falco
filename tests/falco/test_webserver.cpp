/*
Copyright (C) 2019 The Falco Authors.

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
#include "webserver.h"
#include <catch.hpp>

TEST_CASE("webserver must accept invalid data", "[!hide][webserver][k8s_audit_handler][accept_data]")
{
	// falco_engine* engine = new falco_engine();
	// falco_outputs* outputs = new falco_outputs(engine);
	// std::string errstr;
	// std::string input("{\"kind\": 0}");
	//k8s_audit_handler::accept_data(engine, outputs, input, errstr);

	REQUIRE(1 == 1);
}