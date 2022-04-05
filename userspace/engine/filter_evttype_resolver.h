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

#pragma once

#include <filter/parser.h>
#include <string>
#include <set>
#include <memory>

/*!
	\brief Helper class for finding event types
*/
class filter_evttype_resolver: private libsinsp::filter::ast::expr_visitor
{
public:
	/*!
		\brief Collects the evttypes related to the provided event name.
		The event types are inserted in the set provided as parameter.
		The set is not cleared before inserting the elements.
		\param evtname The event name used to search event types. If an empty
		string is passed, all the available evttypes are collected
		\param out The set to be filled with the evttypes
	*/
	void evttypes(std::string evtname, std::set<uint16_t>& out);

	/*!
		\brief Visits a filter AST and collects all the evttypes for which
		the filter expression can be evaluated as true. The event types are
		inserted in the set provided as parameter. The set is not cleared before
		inserting the elements.
		\param filter The filter AST to be explored
		\param out The set to be filled with the evttypes
	*/
	void evttypes(libsinsp::filter::ast::expr* filter, std::set<uint16_t>& out);

	/*!
		\brief Overloaded version of evttypes() that supports filters wrapped
		in shared pointers
	*/
	void evttypes(std::shared_ptr<libsinsp::filter::ast::expr> filter,
		std::set<uint16_t>& out);

private:
	void visit(libsinsp::filter::ast::and_expr* e) override;
	void visit(libsinsp::filter::ast::or_expr* e) override;
	void visit(libsinsp::filter::ast::not_expr* e) override;
	void visit(libsinsp::filter::ast::value_expr* e) override;
	void visit(libsinsp::filter::ast::list_expr* e) override;
	void visit(libsinsp::filter::ast::unary_check_expr* e) override;
	void visit(libsinsp::filter::ast::binary_check_expr* e) override;

	bool m_expect_value;
	std::set<uint16_t> m_last_node_evttypes;
};
