/*
Copyright (C) 2013-2019 Sysdig Inc.

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

#include "sinsp_exception.h"

/*!
  \brief Instances of this exception are thrown when calls to scap_open()
         fail.  The given scap_rc is the error value returned from scap_open().
*/
class scap_open_exception : public sinsp_exception
{
public:
	scap_open_exception(const std::string& error_str, const int32_t scap_rc):
		sinsp_exception(error_str),
		m_scap_rc(scap_rc)
	{ }

	scap_open_exception(const char* const error_str, const int32_t scap_rc):
		sinsp_exception(error_str),
		m_scap_rc(scap_rc)
	{ }

	int32_t scap_rc() const
	{
		return m_scap_rc;
	}

private:
	int32_t m_scap_rc;
};
