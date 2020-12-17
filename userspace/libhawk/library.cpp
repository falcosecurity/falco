/*
Copyright (C) 2020 The Falco Authors.

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

#include "library.h"
#include "exception.h"

#include <dlfcn.h>

libhawk::library::library(const std::string &filename) : m_library_filename(filename) {};

bool libhawk::library::load()
{
	void *handler = nullptr;
	handler = dlopen(m_library_filename.c_str(), RTLD_NOW);
	if (!handler) {
		std::string errmsg(dlerror());
		throw hawk_library_load_exception(m_library_filename, errmsg);
	}
	//todo(fntlnz): need to store the handler or anything to use the library?
	return (handler != nullptr);
}
