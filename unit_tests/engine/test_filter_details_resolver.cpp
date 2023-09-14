// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless ASSERT_EQd by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <gtest/gtest.h>
#include <engine/filter_details_resolver.h>


TEST(DetailsResolver, resolve_ast)
{
    std::string cond = "(spawned_process or evt.type = open) and (proc.name icontains cat or proc.name in (known_procs, ps))";
    auto ast = libsinsp::filter::parser(cond).parse();
    filter_details details;
    details.known_macros.insert("spawned_process");
    details.known_lists.insert("known_procs");
    filter_details_resolver resolver;
    resolver.run(ast.get(), details);

    // Assert fields
    ASSERT_EQ(details.fields.size(), 2);
    ASSERT_NE(details.fields.find("evt.type"), details.fields.end());
    ASSERT_NE(details.fields.find("proc.name"), details.fields.end());

    // Assert macros
    ASSERT_EQ(details.macros.size(), 1);
    ASSERT_NE(details.macros.find("spawned_process"), details.macros.end());
    
    // Assert operators
    ASSERT_EQ(details.operators.size(), 3);
    ASSERT_NE(details.operators.find("="), details.operators.end());
    ASSERT_NE(details.operators.find("icontains"), details.operators.end());
    ASSERT_NE(details.operators.find("in"), details.operators.end());

    // Assert lists
    ASSERT_EQ(details.lists.size(), 1);
    ASSERT_NE(details.lists.find("known_procs"), details.lists.end());
}
