/*
Copyright (C) 2018 Draios inc.

This file is part of falco.

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

#include <memory>

#include "CivetServer.h"

#include "configuration.h"
#include "falco_engine.h"
#include "falco_outputs.h"

class k8s_audit_handler : public CivetHandler
{
public:
	k8s_audit_handler(falco_engine *engine, falco_outputs *outputs);
	virtual ~k8s_audit_handler();

	bool handleGet(CivetServer *server, struct mg_connection *conn);
	bool handlePost(CivetServer *server, struct mg_connection *conn);

	static bool accept_data(falco_engine *engine,
				falco_outputs *outputs,
				std::string &post_data, std::string &errstr);

private:
	falco_engine *m_engine;
	falco_outputs *m_outputs;
	bool accept_uploaded_data(std::string &post_data, std::string &errstr);
};

class falco_webserver
{
public:

	falco_webserver();
	virtual ~falco_webserver();

	void init(falco_configuration *config,
		  falco_engine *engine,
		  falco_outputs *outputs);

	void start();
	void stop();

private:

	falco_engine *m_engine;
	falco_configuration *m_config;
	falco_outputs *m_outputs;
	unique_ptr<CivetServer> m_server;
	unique_ptr<k8s_audit_handler> m_k8s_audit_handler;
};
