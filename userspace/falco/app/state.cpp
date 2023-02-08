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

#include "state.h"

falco::app::state::state()
	: loaded_sources(),
	  enabled_sources(),
	  source_infos(),
	  plugin_configs(),
	  ppm_sc_of_interest(),
	  tp_of_interest(),
	  syscall_buffer_bytes_size(DEFAULT_DRIVER_BUFFER_BYTES_DIM)
{
	config = std::make_shared<falco_configuration>();
	engine = std::make_shared<falco_engine>();
	offline_inspector = std::make_shared<sinsp>();
	outputs = nullptr;
}