/*
Copyright (C) 2019 Sysdig Inc.

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

#include "sinsp.h"
#include <gtest.h>

using namespace libsinsp;

class sinsp_external_processor_dummy : public event_processor
{
	void on_capture_start() override {}
	void process_event(sinsp_evt* evt, event_return rc) override {}
	void add_chisel_metric(statsd_metric* metric) override {}
};

TEST(sinsp, external_event_processor_initialization)
{
	sinsp my_sinsp;
	EXPECT_EQ(my_sinsp.get_external_event_processor(), nullptr);
	sinsp_external_processor_dummy processor;
	my_sinsp.register_external_event_processor(processor);
	EXPECT_EQ(my_sinsp.get_external_event_processor(), &processor);
}

