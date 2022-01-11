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

#include <memory>
#include "tbb/concurrent_queue.h"
#include <falco_engine.h>

class swappable_falco_engine
{
public:
	swappable_falco_engine();
	virtual ~swappable_falco_engine();

	std::shared_ptr<falco_engine> engine();

	// Can be called from a different thread than engine()
	void replace(std::shared_ptr<falco_engine> &new_engine);

private:

	std::shared_ptr<falco_engine> m_falco_engine;

	// If non-empty the head item will be moved to m_falco_engine
	// with the next call to engine()
	tbb::concurrent_queue<std::shared_ptr<falco_engine>> m_pending_falco_engine;
};

