/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

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

#include <gtest.h>
#include "sinsp.h"
#include "../../driver/ppm_events_public.h"

TEST(inspector,get_proc_by_invalid_tid)
{
	sinsp inspector;
	EXPECT_TRUE(NULL == inspector.get_process(-100));
}

TEST(inspector,get_proc_by_valid_tid)
{
	sinsp inspector;
	EXPECT_TRUE(NULL == inspector.get_process(-100));
	sinsp_procinfo newpi(&inspector);
	newpi.m_tgid = -100;
	inspector.m_proctable[-100] = newpi;

	EXPECT_TRUE(NULL != inspector.get_process(-100));
}
