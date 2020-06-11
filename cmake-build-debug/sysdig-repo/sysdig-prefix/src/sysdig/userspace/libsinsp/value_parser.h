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

#pragma once
//
// If this check is used by a filter, extract the constant to compare it to
// Doesn't return the field length because the filtering engine can calculate it.
//

class sinsp_filter_value_parser
{
 public:
	static size_t string_to_rawval(const char* str, uint32_t len, uint8_t *storage, string::size_type max_len, ppm_param_type ptype);
};
