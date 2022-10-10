/*
Copyright (C) 2022 The Falco Authors.

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

#include "application.h"
#include <sys/file.h>

using namespace falco::app;

#define FALCO_LOCK_FILE "falco.lock"

application::run_result application::gain_lock()
{
	m_lock_fd = open(FALCO_LOCK_FILE, O_CREAT | O_WRONLY, 0644);
	if (m_lock_fd < 0)
	{
		return run_result::fatal(std::string("Failed to open " FALCO_LOCK_FILE " lock file: ") + strerror(errno));
	}
	if (flock(m_lock_fd, LOCK_EX | LOCK_NB) == -1)
	{
		return run_result::fatal("A lock is present on " FALCO_LOCK_FILE " Another Falco instance running?");
	}
	return run_result::ok();
}

bool application::release_lock(std::string &errstr)
{
	if (m_lock_fd > 0)
	{
		close(m_lock_fd);
	}
	return true;
}