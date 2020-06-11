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
// mesos_auth.h
//

#pragma once

#include "json/json.h"
#include "mesos_http.h"
#include "uri.h"

static const uint64_t DCOS_ENTERPRISE_TOKEN_REFRESH_S = 60*60*24; // 1 day

class mesos_auth
{
public:
	mesos_auth(const uri::credentials_t& dcos_enterprise_credentials = uri::credentials_t(),
		   std::string auth_hostname = "localhost",
		   int token_refresh_interval = DCOS_ENTERPRISE_TOKEN_REFRESH_S);
	virtual ~mesos_auth();

	virtual void refresh_token();

	// Return the current token. The token may expire at any time
	// after the token has been returned, so it's best to call
	// get_token periodically, which will internally refresh the
	// token if necessary.
	std::string get_token();

protected:
	std::string             m_token;

private:
	void authenticate();

	const uri::credentials_t m_dcos_enterprise_credentials;
	uri m_auth_uri;
	int m_token_refresh_interval;
	time_t m_last_token_refresh_s;
};

