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
//
// k8s_api_error.cpp
//

#include "k8s_api_error.h"

k8s_api_error::k8s_api_error(const msg_data& data, const Json::Value& err):
	m_data(data),
	m_status(get_string(err, "status")),
	m_message(get_string(err, "message")),
	m_reason(get_string(err, "reason")),
	m_details(get_string(err, "details")),
	m_code(get_int(err, "code"))
{
}

k8s_api_error::~k8s_api_error()
{
}

std::string k8s_api_error::get_string(const Json::Value& obj, const std::string& name)
{
	std::string value;
	const Json::Value& val = obj[name];
	if(!val.isNull() && val.isConvertibleTo(Json::stringValue))
	{
		value = val.asString();
	}
	return value;
}

int k8s_api_error::get_int(const Json::Value& obj, const std::string& name)
{
	int value = 0;
	const Json::Value& val = obj[name];
	if(!val.isNull() && val.isConvertibleTo(Json::intValue))
	{
		value = val.asInt();
	}
	return value;
}
