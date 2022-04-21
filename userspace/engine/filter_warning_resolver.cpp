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

#include <sinsp.h>
#include "filter_warning_resolver.h"

static const char* no_value = "<NA>";
static const char* warn_unsafe_na_check = "unsafe-na-check";

static inline bool is_unsafe_field(const string& f)
{
	return !strncmp(f.c_str(), "ka.", strlen("ka."))
		|| !strncmp(f.c_str(), "jevt.", strlen("jevt."));
}

static inline bool is_equality_operator(const string& op)
{
	return op == "==" || op == "=" || op == "!="
		|| op == "in" || op == "intersects" || op == "pmatch";
}

bool filter_warning_resolver::run(
	libsinsp::filter::ast::expr* filter,
	std::set<string>& warnings) const
{
	visitor v;
	auto size = warnings.size();
	v.m_is_equality_check = false;
	v.m_warnings = &warnings;
	filter->accept(&v);
	return warnings.size() > size;
}

// todo(jasondellaluce): use an hard-coded map once we support more warnings
bool filter_warning_resolver::format(
	const std::string& code,
	std::string& out) const
{
	if (code == warn_unsafe_na_check)
	{
		out = "comparing a field value with <NA> is unsafe and can lead to "
			"unpredictable behavior of the rule condition. If you need to "
			" check for the existence of a field, consider using the "
			"'exists' operator instead.";
		return true;
	}
	return false;
}

void filter_warning_resolver::visitor::visit(
	libsinsp::filter::ast::binary_check_expr* e)
{
	if (is_unsafe_field(e->field) && is_equality_operator(e->op))
	{
		m_is_equality_check = true;
		e->value->accept(this);
		m_is_equality_check = false;
	}
}

void filter_warning_resolver::visitor::visit(
	libsinsp::filter::ast::value_expr* e)
{
	if (m_is_equality_check && e->value == no_value)
	{
		m_warnings->insert(warn_unsafe_na_check);
	}
}

void filter_warning_resolver::visitor::visit(
	libsinsp::filter::ast::list_expr* e)
{
	if (m_is_equality_check
		&& std::find(e->values.begin(), e->values.end(), no_value) != e->values.end())
	{
		m_warnings->insert(warn_unsafe_na_check);
	}
}