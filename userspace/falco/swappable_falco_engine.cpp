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

#include "swappable_falco_engine.h"

swappable_falco_engine::swappable_falco_engine()
{
	m_falco_engine = std::make_shared<falco_engine>();
}

swappable_falco_engine::~swappable_falco_engine()
{

}

std::shared_ptr<falco_engine> swappable_falco_engine::engine()
{
	std::shared_ptr<falco_engine> new_engine;
	while(m_pending_falco_engine.try_pop(new_engine))
	{
		m_falco_engine=new_engine;
	}

	return m_falco_engine;
}

void swappable_falco_engine::replace(std::shared_ptr<falco_engine> &new_engine)
{
	m_pending_falco_engine.push(new_engine);
}
