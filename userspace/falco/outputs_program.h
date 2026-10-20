// SPDX-License-Identifier: Apache-2.0
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

#pragma once

#include "outputs.h"

#include <sys/types.h>

namespace falco {
namespace outputs {

class output_program : public abstract_output {
	bool init(const config &oc,
	          bool buffered,
	          const std::string &hostname,
	          bool json_output,
	          std::string &err) override;

	void output(const message *msg) override;

	void cleanup() override;

	void reopen() override;

private:
	void open_pfile();

	// Close the pipe to the program, then wait for the program to exit, or only
	// reap it later without blocking if `wait` is false.
	void close_pfile(bool wait);

	// Reap the program whose pipe was closed without waiting, if it has exited.
	// Return false if it is still running.
	bool reap_closed_program();

	FILE *m_pfile = nullptr;
	pid_t m_pid = -1;
	pid_t m_closed_pid = -1;
};

}  // namespace outputs
}  // namespace falco
