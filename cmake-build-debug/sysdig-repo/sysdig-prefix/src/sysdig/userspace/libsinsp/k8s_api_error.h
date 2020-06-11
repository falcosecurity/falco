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
// k8s_api_error.h
//

#pragma once

#include "json/json.h"
#include "k8s_component.h"

class k8s_api_error
{
public:
	typedef k8s_component::msg_reason msg_reason;
	typedef k8s_component::msg_data msg_data;

	k8s_api_error(const msg_data& data, const Json::Value& err);

	~k8s_api_error();

	const std::string& component_name() const;
	const std::string& component_id() const;
	const std::string& component_namespace() const;
	const std::string& component_kind() const;

	const std::string& metadata() const;
	const std::string& status() const;
	const std::string& message() const;
	const std::string& reason() const;
	const std::string& details() const;
	int code() const;

	std::string to_string() const;

private:
	static std::string get_string(const Json::Value& obj, const std::string& name);
	static int get_int(const Json::Value& obj, const std::string& name);

	msg_data    m_data;
	std::string m_meta;
	std::string m_status;
	std::string m_message;
	std::string m_reason;
	std::string m_details;
	int         m_code;
};

inline const std::string& k8s_api_error::component_name() const
{
	return m_data.m_name;
}

inline const std::string& k8s_api_error::component_id() const
{
	return m_data.m_uid;
}

inline const std::string& k8s_api_error::component_namespace() const
{
	return m_data.m_namespace;
}

inline const std::string& k8s_api_error::component_kind() const
{
	return m_data.m_kind;
}

inline const std::string& k8s_api_error::metadata() const
{
	return m_meta;
}

inline const std::string& k8s_api_error::status() const
{
	return m_status;
}

inline const std::string& k8s_api_error::message() const
{
	return m_message;
}

inline const std::string& k8s_api_error::reason() const
{
	return m_reason;
}

inline const std::string& k8s_api_error::details() const
{
	return m_details;
}

inline int k8s_api_error::code() const
{
	return m_code;
}

inline std::string k8s_api_error::to_string() const
{
	std::ostringstream os;
	os << "K8s API error; Status: " << m_status << ", "
		"Message: " << m_message << ", "
		"Reason: " << m_reason << ", "
		"Details: " << m_details << ", "
		"Code: " << m_message;
	return os.str();
}
