// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <libsinsp/filter_compare.h>
#include <libsinsp/sinsp_exception.h>

// Returns true when a base cmpop can legally be combined with a list modifier.
// Mirrors the s_binary_str_ops set in libs' filter/parser.cpp: only string
// comparison operators support oneof/anyof/allof in the filter grammar.
inline bool cmpop_supports_modifier(cmpop op) {
	switch(op) {
	case CO_EQ:
	case CO_NE:
	case CO_CONTAINS:
	case CO_ICONTAINS:
	case CO_BCONTAINS:
	case CO_STARTSWITH:
	case CO_BSTARTSWITH:
	case CO_ENDSWITH:
	case CO_GLOB:
	case CO_IGLOB:
	case CO_REGEX:
		return true;
	default:
		return false;
	}
}

// Returns true when `op` is a string operator legally combined with a list
// modifier, e.g. "startswith oneof", "contains allof", "glob anyof".
// Returns false for plain operators, unknown tokens, and illegal combinations
// such as "in oneof" or ">= oneof".
inline bool is_str_operator_with_modifier(const std::string& op) {
	try {
		auto cmp = str_to_cmpop_with_modifier(op);
		return cmp.mod != CMPOP_MOD_NONE && cmpop_supports_modifier(cmp.op);
	} catch(const sinsp_exception&) {
		return false;
	}
}
