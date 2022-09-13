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

#include "rule_loader.h"
#include "rule_loader_collector.h"

namespace rule_loader
{

/*!
    \brief Reads the contents of a ruleset
*/
class reader
{
public:
    virtual ~reader() = default;

    /*!
		\brief Reads the contents of a ruleset and uses a collector to store
        thew new definitions
	*/
	virtual bool read(configuration& cfg, collector& loader);
};

}; // namespace rule_loader