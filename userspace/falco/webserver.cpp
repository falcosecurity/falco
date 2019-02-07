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

#include <stdio.h>
#include <string.h>

#include "falco_common.h"
#include "webserver.h"
#include "json_evt.h"

using json = nlohmann::json;
using namespace std;

k8s_audit_handler::k8s_audit_handler(falco_engine *engine, falco_outputs *outputs)
	: m_engine(engine), m_outputs(outputs)
{
}

k8s_audit_handler::~k8s_audit_handler()
{
}

bool k8s_audit_handler::accept_data(falco_engine *engine,
				    falco_outputs *outputs,
				    std::string &data,
				    std::string &errstr)
{
	std::list<json_event> jevts;
	json j;

	try {
		j = json::parse(data);
	}
	catch (json::parse_error& e)
	{
		errstr = string("Could not parse data: ") + e.what();
		return false;
	}

	if(!engine->parse_k8s_audit_json(j, jevts))
	{
		errstr = string("Data not recognized as a k8s audit event");
		return false;
	}

	for(auto &jev : jevts)
	{
		std::unique_ptr<falco_engine::rule_result> res;
		res = engine->process_k8s_audit_event(&jev);

		if(res)
		{
			try {
				outputs->handle_event(res->evt, res->rule,
							res->source, res->priority_num,
							res->format);
			}
			catch(falco_exception &e)
			{
				errstr = string("Internal error handling output: ") + e.what();
				fprintf(stderr, "%s\n", errstr.c_str());
				return false;
			}
		}
	}

	return true;
}

bool k8s_audit_handler::accept_uploaded_data(std::string &post_data, std::string &errstr)
{
	return k8s_audit_handler::accept_data(m_engine, m_outputs, post_data, errstr);
}


bool k8s_audit_handler::handleGet(CivetServer *server, struct mg_connection *conn)
{
	mg_send_http_error(conn, 405, "GET method not allowed");

	return true;
}

// The version in CivetServer.cpp has valgrind compliants due to
// unguarded initialization of c++ string from buffer.
static void get_post_data(struct mg_connection *conn, std::string &postdata)
{
        mg_lock_connection(conn);
        char buf[2048];
        int r = mg_read(conn, buf, sizeof(buf));
        while (r > 0) {
                postdata.append(buf, r);
                r = mg_read(conn, buf, sizeof(buf));
        }
        mg_unlock_connection(conn);
}

bool k8s_audit_handler::handlePost(CivetServer *server, struct mg_connection *conn)
{
	// Ensure that the content-type is application/json
	const char *ct = server->getHeader(conn, string("Content-Type"));

	if(ct == NULL || string(ct) != "application/json")
	{
		mg_send_http_error(conn, 400, "Wrong Content Type");

		return true;
	}

	std::string post_data;
	get_post_data(conn, post_data);
	std::string errstr;

	if(!accept_uploaded_data(post_data, errstr))
	{
		errstr = "Bad Request: " + errstr;
		mg_send_http_error(conn, 400, "%s", errstr.c_str());

		return true;
	}

	std::string ok_body = "<html><body>Ok</body></html>";
	mg_send_http_ok(conn, "text/html", ok_body.size());
	mg_printf(conn, "%s", ok_body.c_str());

	return true;
}

falco_webserver::falco_webserver()
	: m_config(NULL)
{
}

falco_webserver::~falco_webserver()
{
	stop();
}

void falco_webserver::init(falco_configuration *config,
			   falco_engine *engine,
			   falco_outputs *outputs)
{
	m_config = config;
	m_engine = engine;
	m_outputs = outputs;
}

template<typename T, typename ...Args>
std::unique_ptr<T> make_unique( Args&& ...args )
{
    return std::unique_ptr<T>( new T( std::forward<Args>(args)... ) );
}

void falco_webserver::start()
{
	if(m_server)
	{
		stop();
	}

	if(!m_config)
	{
		throw falco_exception("No config provided to webserver");
	}

	if(!m_engine)
	{
		throw falco_exception("No engine provided to webserver");
	}

	if(!m_outputs)
	{
		throw falco_exception("No outputs provided to webserver");
	}

	std::vector<std::string> cpp_options = {
		"num_threads", to_string(1)
	};

	if (m_config->m_webserver_ssl_enabled)
	{
		cpp_options.push_back("listening_ports");
		cpp_options.push_back(to_string(m_config->m_webserver_listen_port) + "s");
		cpp_options.push_back("ssl_certificate");
		cpp_options.push_back(m_config->m_webserver_ssl_certificate);
	} else {
		cpp_options.push_back("listening_ports");
		cpp_options.push_back(to_string(m_config->m_webserver_listen_port));
	}

	try {
		m_server = make_unique<CivetServer>(cpp_options);
	}
	catch (CivetException &e)
	{
		throw falco_exception(std::string("Could not create embedded webserver: ") + e.what());
	}
	if(!m_server->getContext())
	{
		throw falco_exception("Could not create embedded webserver");
	}

	m_k8s_audit_handler = make_unique<k8s_audit_handler>(m_engine, m_outputs);
	m_server->addHandler(m_config->m_webserver_k8s_audit_endpoint, *m_k8s_audit_handler);
}

void falco_webserver::stop()
{
	if(m_server)
	{
		m_server = NULL;
		m_k8s_audit_handler = NULL;
	}
}
