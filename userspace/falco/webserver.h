/*
Copyright (C) 2019 The Falco Authors.

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
	k8s_audit_handler(std::shared_ptr<falco_engine> engine, std::shared_ptr<falco_outputs> outputs);
	virtual ~k8s_audit_handler();

	bool handleGet(CivetServer *server, struct mg_connection *conn);
	bool handlePost(CivetServer *server, struct mg_connection *conn);

	static bool accept_data(std::shared_ptr<falco_engine> engine,
				std::shared_ptr<falco_outputs> outputs,
				std::string &post_data, std::string &errstr);

	static std::string m_k8s_audit_event_source;

private:
	std::shared_ptr<falco_engine> m_engine;
	std::shared_ptr<falco_outputs> m_outputs;
	bool accept_uploaded_data(std::string &post_data, std::string &errstr);
};

class k8s_healthz_handler : public CivetHandler
{
public:
	k8s_healthz_handler()
	{
	}

	virtual ~k8s_healthz_handler()
	{
	}

	bool handleGet(CivetServer *server, struct mg_connection *conn);
};

class falco_webserver
{
public:
	falco_webserver();
	virtual ~falco_webserver();

	void init(std::shared_ptr<falco_configuration> config,
		  std::shared_ptr<falco_engine> engine,
		  std::shared_ptr<falco_outputs> outputs);

	void start();
	void stop();

private:
	std::shared_ptr<falco_engine> m_engine;
	std::shared_ptr<falco_configuration> m_config;
	std::shared_ptr<falco_outputs> m_outputs;
	unique_ptr<CivetServer> m_server;
	unique_ptr<k8s_audit_handler> m_k8s_audit_handler;
	unique_ptr<k8s_healthz_handler> m_k8s_healthz_handler;
};
