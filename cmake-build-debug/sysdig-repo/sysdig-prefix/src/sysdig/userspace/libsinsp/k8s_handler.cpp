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
// k8s_handler.cpp
//
#ifndef CYGWING_AGENT

#include "k8s_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"

// to match regular K8s API message format,
// error is wrapped into a single-entry array
std::string k8s_handler::ERROR_FILTER =
	"{"
	"  type: \"ERROR\","
	"  apiVersion: .apiVersion,"
	"  kind: .kind,"
	"  items:"
	"  ["
	"   . |"
	"   {"
	"     metadata: .metadata,"
	"     status: .status,"
	"     message: .message,"
	"     reason: .reason,"
	"     details: .details,"
	"     code: .code"
	"   }"
	"  ]"
	"}";

k8s_handler::k8s_handler(const std::string& id,
	bool is_captured,
#ifdef HAS_CAPTURE
	std::string url,
	const std::string& path,
	const std::string& state_filter,
	const std::string& event_filter,
	const std::string& null_filter,
	collector_ptr_t collector,
	const std::string& http_version,
	int timeout_ms,
	ssl_ptr_t ssl,
	bt_ptr_t bt,
	bool watch,
	bool connect,
	ptr_t dependency_handler,
	bool blocking_socket,
#endif // HAS_CAPTURE
	unsigned max_messages,
	k8s_state_t* state): m_state(state),
		m_id(id + "_state"),
#ifdef HAS_CAPTURE
		m_collector(collector),
		m_path(path + ((path.find('?') == std::string::npos) ? "?pretty=false" : "&pretty=false")),
		m_state_filter(state_filter),
		m_event_filter(event_filter),
		m_null_filter(null_filter),
		m_filter(&m_state_filter),
		m_timeout_ms(timeout_ms),
		m_url(url),
		m_http_version(http_version),
		m_ssl(ssl),
		m_bt(bt),
		m_watch(watch),
		m_connect(connect),
		m_dependency_handler(dependency_handler),
		m_blocking_socket(blocking_socket),
#endif // HAS_CAPTURE
		m_max_messages(max_messages),
		m_is_captured(is_captured)
{
#ifdef HAS_CAPTURE
	g_logger.log("Creating K8s " + name() + " (" + m_id + ") "
				 "handler object for [" + uri(m_url).to_string(false) + m_path + ']',
				 sinsp_logger::SEV_DEBUG);
	if(m_connect)
	{
		g_logger.log(std::string("K8s (" + m_id + ") creating handler for " +
							 uri(m_url).to_string(false) + m_path), sinsp_logger::SEV_DEBUG);
		m_handler = std::make_shared<handler_t>(*this, m_id, m_url, m_path, m_http_version,
											 m_timeout_ms, m_ssl, m_bt, !m_blocking_socket, m_blocking_socket);
		m_handler->set_json_callback(&k8s_handler::set_event_json);

		// filter order is important; there are four kinds of filters:
		// 1.a state filter (filters init state JSONs)
		// 1.b event filter (filters watch JSONs)
		// 2. null filter  (filters init state JSONs when there are no K8s entities)
		// 3. error filter (filters errors)
		// and they must come in the following order:
		// 1.a OR 1.b, then 2. (for state only), then 3. (always)
		// mixing the order will produce erroneous results because
		// null and error filters will successfully parse regular messages
		// and prevent proper processing
		m_handler->add_json_filter(*m_filter);
		if(!m_null_filter.empty())
		{
			m_handler->add_json_filter(m_null_filter);
		}
		m_handler->add_json_filter(ERROR_FILTER);

		m_handler->close_on_chunked_end(false);
		this->connect();
	}
#endif // HAS_CAPTURE
}

k8s_handler::~k8s_handler()
{
}

void k8s_handler::make_http()
{
#ifdef HAS_CAPTURE
	if(m_connect && m_collector)
	{
		if(!m_handler)
		{
			g_logger.log("K8s (" + m_id + ") creating handler for " +
						 uri(m_url).to_string(false) + m_path, sinsp_logger::SEV_INFO);
			m_handler = std::make_shared<handler_t>(*this, m_id, m_url, m_path, m_http_version,
												 m_timeout_ms, m_ssl, m_bt, true, m_blocking_socket);
			m_handler->set_json_callback(&k8s_handler::set_event_json);
		}
		else if(m_collector->has(m_handler))
		{
			m_collector->remove(m_handler);
		}

		// adjust filters for event handler
		// (see comment in ctor for explanation)
		// - null filter is only needed for init state
		m_handler->remove_json_filter(m_null_filter);
		// - state filter will be replaced with the event filter below
		m_handler->remove_json_filter(m_state_filter);
		m_filter = &m_event_filter;
		// - error filter should be there, but just in case let's double-check
		if(!m_handler->has_json_filter(ERROR_FILTER))
		{
			g_logger.log("K8s (" + m_id + ") error filter was not present in state handler, adding it for events.",
						 sinsp_logger::SEV_WARNING);
			m_handler->add_json_filter(ERROR_FILTER);
		}
		// - good event filter must always be before error event filter
		m_handler->add_json_filter(*m_filter, ERROR_FILTER);
		// end filter adjustment

		m_handler->set_path(m_path);
		m_handler->set_id(m_id);
		m_collector->set_steady_state(true);
		m_watching = true;
		m_blocking_socket = false;
		m_handler->close_on_chunked_end(false);

		m_req_sent = false;
		m_resp_recvd = false;
		connect();
		m_handler->set_socket_option(SOCK_NONBLOCK);
	}
#endif // HAS_CAPTURE
}

void k8s_handler::check_enabled()
{
#ifdef HAS_CAPTURE
	if(!m_handler->is_enabled())
	{
		g_logger.log("k8s_handler (" + m_id +
					") check_enabled() enabling socket in collector", sinsp_logger::SEV_TRACE);
		m_handler->enable();
	}
	else
	{
		g_logger.log("k8s_handler (" + m_id +
					") check_enabled() socket in collector is enabled, "
					"checking collector status.", sinsp_logger::SEV_TRACE);
		check_collector_status();
	}
#endif // HAS_CAPTURE
}

bool k8s_handler::connect()
{
#ifdef HAS_CAPTURE
	if(m_collector && m_handler)
	{
		if(!m_collector->has(m_handler))
		{
			g_logger.log(std::string("k8s_handler (" + m_id +
									 ") k8s_handler::connect() adding handler to collector"), sinsp_logger::SEV_TRACE);
			m_collector->add(m_handler);
			return false;
		}
		if(m_handler->is_connecting())
		{
			g_logger.log(std::string("k8s_handler (" + m_id +
									 "), k8s_handler::connect() connecting to " + m_handler->get_url().to_string(false)), sinsp_logger::SEV_TRACE);
			return false;
		}
		if(m_handler->is_connected())
		{
			g_logger.log("k8s_handler (" + m_id +
						") k8s_handler::connect() socket is connected.", sinsp_logger::SEV_TRACE);
			check_enabled();
			return true;
		}
	}
	else if (m_collector && !m_url.empty())
	{
		g_logger.log(std::string("k8s_handler (" + m_id +
								 ") k8s_handler::connect(), http is null, (re)creating ... "),
								 sinsp_logger::SEV_WARNING);
		make_http();
	}
#endif // HAS_CAPTURE
	return false;
}

void k8s_handler::send_data_request()
{
#ifdef HAS_CAPTURE
	if(m_handler)
	{
		if(!m_req_sent)
		{
			if(m_handler->is_connected())
			{
				g_logger.log("k8s_handler (" + m_id + ") sending request to " +
							 m_handler->get_url().to_string(false) + m_path,
							 sinsp_logger::SEV_DEBUG);
				m_handler->send_request();
				m_req_sent = true;
			}
			else if(m_handler->is_connecting())
			{
				g_logger.log("k8s_handler (" + m_id + ") is connecting to " +
							 m_handler->get_url().to_string(false),
							 sinsp_logger::SEV_DEBUG);
			}
		}
	}
	else
	{
		throw sinsp_exception("k8s_handler (" + m_id + ") HTTP client (" + uri(m_url).to_string(false) + ") is null.");
	}
#endif // HAS_CAPTURE
}

void k8s_handler::receive_response()
{
#ifdef HAS_CAPTURE
	if(m_handler)
	{
		if(m_req_sent)
		{
			if(!m_watching)
			{
				if(m_handler->get_all_data())
				{
					m_data_received = true;
				}
				else
				{
					throw sinsp_exception("K8s k8s_handler::receive_response(): no data received.");
				}
			}
			else
			{
				throw sinsp_exception("K8s k8s_handler::receive_response(): invalid call (in watch mode).");
			}
		}
		else
		{
			throw sinsp_exception("K8s k8s_handler::receive_response(): invalid call (request not sent).");
		}
	}
	else
	{
		throw sinsp_exception("K8s k8s_handler::receive_response(): handler is null.");
	}
#endif // HAS_CAPTURE
}

bool k8s_handler::is_alive() const
{
#ifdef HAS_CAPTURE
	if(m_handler && !m_handler->is_connecting() && !m_handler->is_connected())
	{
		g_logger.log("k8s_handler (" + m_id + ") connection (" + m_handler->get_url().to_string(false) + ") loss.",
					 sinsp_logger::SEV_WARNING);
		return false;
	}
#endif // HAS_CAPTURE
	return true;
}

void k8s_handler::check_collector_status()
{
#ifdef HAS_CAPTURE
	if(m_collector)
	{
		if(!m_collector->has(m_handler))
		{
			m_handler.reset();
			make_http();
		}
	}
	else
	{
		throw sinsp_exception("k8s_handler (" + m_id + ") collector is null.");
	}
#endif // HAS_CAPTURE
}

void k8s_handler::check_state()
{
#ifdef HAS_CAPTURE
	if(m_collector && m_handler)
	{
		if(m_resp_recvd && m_watch && !m_watching)
		{
			g_logger.log("k8s_handler (" + m_id + ") switching to watch connection for " +
						 uri(m_url).to_string(false) + m_path,
						 sinsp_logger::SEV_DEBUG);
			std::string::size_type pos = m_id.find("_state");
			if(pos != std::string::npos)
			{
				m_id = m_id.substr(0, pos).append("_event");
			}
			pos = m_path.find("/watch");
			if(pos == std::string::npos)
			{
				pos = m_path.rfind('/');
				if(pos != std::string::npos)
				{
					m_path.insert(pos, "/watch");
				}
				else
				{
					throw sinsp_exception("k8s_handler (" + m_id + "), invalid URL path: " + m_path);
				}
			}
			m_handler->set_socket_option(SOCK_NONBLOCK);
			make_http();
		}
		if(m_watching && m_id.find("_state") == std::string::npos && m_handler->wants_send())
		{
			m_req_sent = false;
			m_resp_recvd = false;
		}
	}
#endif // HAS_CAPTURE
}

bool k8s_handler::connection_error() const
{
#ifdef HAS_CAPTURE
	if(m_handler)
	{
		return m_handler->connection_error();
	}
#endif // HAS_CAPTURE
	return false;
}

void k8s_handler::collect_data()
{
#ifdef HAS_CAPTURE
	if(m_collector && m_handler)
	{
		process_events(); // there may be leftovers from state connection closed by collector
		check_state(); // switch to events, if needed
		g_logger.log("k8s_handler (" + m_id + ")::collect_data(), checking connection to " + uri(m_url).to_string(false), sinsp_logger::SEV_DEBUG);
		if(m_handler->is_connecting())
		{
			g_logger.log("k8s_handler (" + m_id + ")::collect_data(), connecting to " + uri(m_url).to_string(false), sinsp_logger::SEV_DEBUG);
			return;
		}
		else if(m_handler->is_connected())
		{
			if(!m_connect_logged)
			{
				g_logger.log("k8s_handler (" + m_id + ")::collect_data(), connected to " + uri(m_url).to_string(false) + m_path,  sinsp_logger::SEV_DEBUG);
				m_connect_logged = true;
			}
			check_enabled();
			if(!m_req_sent)
			{
				g_logger.log("k8s_handler (" + m_id + ")::collect_data() [" + uri(m_url).to_string(false) + "], requesting data "
							 "from " + m_path + "... m_blocking_socket=" + std::to_string(m_blocking_socket) + ", m_watching=" + std::to_string(m_watching),
							 sinsp_logger::SEV_DEBUG);
				send_data_request();
				if(m_blocking_socket && !m_watching)
				{
					receive_response();
					process_events();
					return;
				}
			}
			if(m_collector->subscription_count())
			{
				g_logger.log("k8s_handler (" + m_id + ")::collect_data() [" + uri(m_url).to_string(false) + "], getting data "
							 "from " + m_path + "...",  sinsp_logger::SEV_DEBUG);
				m_collector->get_data();
				g_logger.log("k8s_handler (" + m_id + ")::collect_data(), " + std::to_string(m_events.size()) +
							 " events from " + uri(m_url).to_string(false) + m_path, sinsp_logger::SEV_DEBUG);
				if(m_events.size())
				{
					g_logger.log("k8s_handler (" + m_id + ")::collect_data(), data from " + uri(m_url).to_string(false) + m_path +
								 ", event count=" + std::to_string(m_events.size()), sinsp_logger::SEV_DEBUG);
					process_events();
					check_state();
				}
				else
				{
					g_logger.log("k8s_handler (" + m_id + ") collect_data(), no data from " + uri(m_url).to_string(false) + m_path,
							 sinsp_logger::SEV_DEBUG);
				}
			}
			else
			{
				g_logger.log("k8s_handler (" + m_id + ") collect_data(), no subscriptions to " + uri(m_url).to_string(false) + m_path,
						 sinsp_logger::SEV_DEBUG);
			}
			return;
		}
		else
		{
			connect();
		}
		m_req_sent = false;
	}
	else
	{
		g_logger.log("k8s_handler (" + m_id + "), http interface not (yet?) created for " + uri(m_url).to_string(false) + ").",
					 sinsp_logger::SEV_TRACE);
	}
#endif // HAS_CAPTURE
}

k8s_handler::msg_data k8s_handler::get_msg_data(const std::string& type, const std::string& kind, const Json::Value& json)
{
	msg_data data;
	if(!type.empty())
	{
		if(type[0] == 'A') { data.m_reason = k8s_component::COMPONENT_ADDED; }
		else if(type[0] == 'M') { data.m_reason = k8s_component::COMPONENT_MODIFIED; }
		else if(type[0] == 'D') { data.m_reason = k8s_component::COMPONENT_DELETED; }
		else if(type[0] == 'N') { data.m_reason = k8s_component::COMPONENT_NONEXISTENT; }
		else if(type[0] == 'E') { data.m_reason = k8s_component::COMPONENT_ERROR; }
	}
	else
	{
		return data;
	}

	data.m_kind = kind;

	Json::Value name = json["name"];
	if(!name.isNull())
	{
		data.m_name = name.asString();
	}
	Json::Value uid = json["uid"];
	if(!uid.isNull())
	{
		data.m_uid = uid.asString();
	}
	Json::Value nspace = json["namespace"];
	if(!nspace.isNull())
	{
		data.m_namespace = nspace.asString();
	}

	return data;
}

void k8s_handler::handle_json(Json::Value&& root)
{
	/*if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
	{
		g_logger.log(json_as_string(root), sinsp_logger::SEV_TRACE);
	}*/

	if(!m_state)
	{
#ifdef HAS_CAPTURE
		throw sinsp_exception("k8s_handler (" + m_id + "), state is null for " + uri(m_url).to_string(false) + ").");
#else
		throw sinsp_exception("k8s_handler (" + m_id + "), state is null.");
#endif // HAS_CAPTURE
	}
	const Json::Value& type = root["type"];
	if(!type.isNull())
	{
		if(type.isConvertibleTo(Json::stringValue))
		{
			const Json::Value& kind = root["kind"];
			if(!kind.isNull())
			{
				if(kind.isConvertibleTo(Json::stringValue))
				{
					std::string t = type.asString();
					std::string k = kind.asString();
					for(const Json::Value& item : root["items"])
					{
						msg_data data = get_msg_data(t, k, item);
						/*
						  uncomment to test proper error handling

						//if(name() == "replicasets") // vary name to verify (non)critical component error handling
						if(name() == "pods")
						{
							std::string j = "{"
											" \"metadata\": \"{}\","
											" \"status\": \"Failure\","
											" \"message\": \"the server could not find the requested resource\","
											" \"reason\": \"NotFound\","
											" \"details\": \"{}\","
											" \"code\": 404"
											"}";
							Json::Value i;
							Json::Reader().parse(j, i);
							data.m_reason = k8s_component::COMPONENT_ERROR;
							handle_error(data, i);
							continue;
						}
						*/
						std::string reason_type = data.get_reason_desc();
						if(data.m_reason == k8s_component::COMPONENT_ADDED)
						{
							if(m_state->has(data.m_uid))
							{
								std::ostringstream os;
								os << "K8s " + reason_type << " message received by " << m_id <<
#ifdef HAS_CAPTURE
									  " [" << uri(m_url).to_string(false) << "]"
#endif // HAS_CAPTURE
									  "for existing " << data.m_kind << " [" << data.m_uid << "], updating only.";
								g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
							}
						}
						else if(data.m_reason == k8s_component::COMPONENT_MODIFIED)
						{
							if(!m_state->has(data.m_uid))
							{
								std::ostringstream os;
								os << "K8s " << reason_type << " message received by " << m_id  <<
#ifdef HAS_CAPTURE
									  " [" << uri(m_url).to_string(false) << "]"
#endif // HAS_CAPTURE
									  " for non-existing " << data.m_kind << " [" << data.m_uid << "], giving up.";
								g_logger.log(os.str(), sinsp_logger::SEV_WARNING);
								continue;
							}
						}
						else if(data.m_reason == k8s_component::COMPONENT_DELETED)
						{
							if(!m_state->has(data.m_uid))
							{
								std::ostringstream os;
								os << "K8s " + reason_type + " message received by " << m_id <<
#ifdef HAS_CAPTURE
									  " [" << uri(m_url).to_string(false) << "]"
#endif // HAS_CAPTURE
									  " for non-existing " << data.m_kind << " [" << data.m_uid << "], giving up.";
								g_logger.log(os.str(), sinsp_logger::SEV_WARNING);
								continue;
							}
						}
						else if(data.m_reason == k8s_component::COMPONENT_ERROR)
						{
							handle_error(data, item);
							continue;
						}
						else
						{
							if(data.m_reason == k8s_component::COMPONENT_NONEXISTENT)
							{
								g_logger.log(std::string("Non-existent K8S component (" + name() + "), reason: ") +
											 std::to_string(data.m_reason), sinsp_logger::SEV_DEBUG);
							}
							else
							{
								g_logger.log(std::string("Unsupported K8S " + name() + " event reason: ") +
											 std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
							}
							continue;
						}
						/*if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
						{
							g_logger.log("K8s handling item:\n" + json_as_string(item), sinsp_logger::SEV_TRACE);
						}*/
						if(handle_component(item, &data))
						{
							std::ostringstream os;
							os << "K8s [" + reason_type + ", " << data.m_kind <<
								", " << data.m_name << ", " << data.m_uid << "]";
							g_logger.log(os.str(), sinsp_logger::SEV_INFO);
							m_state->update_cache(k8s_component::get_type(name()));
						}
						else
						{
							g_logger.log("K8s: error occurred while handling " + reason_type +
										 " event for " + data.m_kind + ' ' + data.m_name + " [" +
										 data.m_uid + ']', sinsp_logger::SEV_ERROR);
						}
					} // end for items
				}
			}
		}
		else
		{
			g_logger.log(std::string("K8S event type is not string."), sinsp_logger::SEV_ERROR);
		}
	}
	else
	{
		g_logger.log(std::string("K8S event type is null."), sinsp_logger::SEV_ERROR);
	}
}

#ifdef HAS_CAPTURE

bool k8s_handler::is_ip_address(const std::string& addr)
{
	struct sockaddr_in serv_addr = {0};
	return inet_aton(addr.c_str(), &serv_addr.sin_addr);
}

k8s_handler::ip_addr_list_t k8s_handler::hostname_to_ip(const std::string& hostname)
{
	ip_addr_list_t ip_addrs;
	struct addrinfo *servinfo = 0;

	struct addrinfo hints = {0};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if((getaddrinfo(hostname.c_str(), NULL, &hints, &servinfo)) != 0)
	{
		g_logger.log("Can't determine IP address for hostname: " + hostname, sinsp_logger::SEV_WARNING);
		return ip_addrs;
	}

	for(struct addrinfo* p = servinfo; p != NULL; p = p->ai_next)
	{
		struct sockaddr_in* h = (struct sockaddr_in*)p->ai_addr;
		ip_addrs.emplace(inet_ntoa(h->sin_addr));
	}

	freeaddrinfo(servinfo);
	return ip_addrs;
}

#endif // HAS_CAPTURE

bool k8s_handler::dependency_ready() const
{
#ifdef HAS_CAPTURE
	g_logger.log("k8s_handler (" + m_id + ") dependency "
				 "(" + m_dependency_handler->get_id() + ") ready: " +
				 std::to_string(m_dependency_handler->is_state_built()),
				 sinsp_logger::SEV_TRACE);
	return m_dependency_handler->is_state_built();
#else
	return true;
#endif // HAS_CAPTURE
}

void k8s_handler::process_events()
{
	if(dependency_ready())
	{
		unsigned counter = 0;
		for(auto evt = m_events.begin(); evt != m_events.end();)
		{
			m_state_processing_started = true;
			if(++counter >= get_max_messages()) { break; }
			if(*evt && !(*evt)->isNull())
			{
				if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
				{
					g_logger.log("k8s_handler (" + m_id + ") processing event data:\n" + json_as_string(*(*evt)),
								 sinsp_logger::SEV_TRACE);
				}
#ifdef HAS_CAPTURE
				if(m_is_captured)
				{
					m_state->enqueue_capture_event(**evt);
				}
#endif // HAS_CAPTURE
				handle_json(std::move(**evt));
			}
			else
			{
				g_logger.log("k8s_handler (" + m_id + ") error " +
#ifdef HAS_CAPTURE
							 "(" + uri(m_url).to_string(false) + ") " +
#endif // HAS_CAPTURE
							(!(*evt) ? "data is null." : ((*evt)->isNull() ? "JSON is null." : "Unknown")),
							sinsp_logger::SEV_ERROR);
			}
			evt = m_events.erase(evt);
		}
		if(!m_state_built && m_state_processing_started && !m_events.size()) { m_state_built = true; }
	}
}

void k8s_handler::set_event_json(json_ptr_t json, const std::string&)
{
	g_logger.log("k8s_handler adding event, (" + m_id + ") has " + std::to_string(m_events.size())
#ifdef HAS_CAPTURE
				+ " events from " + uri(m_url).to_string(false)
#endif // HAS_CAPTURE
				, sinsp_logger::SEV_TRACE);
	// empty JSON is fine here; if there are no entities, state and first watch will pass nothing in here
	// null is checked when processing
	m_events.emplace_back(json);
	g_logger.log("k8s_handler added event, (" + m_id + ") has " + std::to_string(m_events.size())
#ifdef HAS_CAPTURE
				+ " events from " + uri(m_url).to_string(false)
#endif // HAS_CAPTURE
				, sinsp_logger::SEV_TRACE);
#ifdef HAS_CAPTURE
	if(!m_resp_recvd) { m_resp_recvd = true; }
#endif // HAS_CAPTURE
}

k8s_pair_list k8s_handler::extract_object(const Json::Value& object)
{
	k8s_pair_list entry_list;
	if(!object.isNull() && object.isObject())
	{
		Json::Value::Members members = object.getMemberNames();
		for (auto& member : members)
		{
			const Json::Value& val = object[member];
			if(!val.isNull() && val.isString())
			{
				entry_list.emplace_back(k8s_pair_t(member, val.asString()));
			}
		}
	}
	return entry_list;
}

std::string k8s_handler::name() const
{
	std::string n;
#ifdef HAS_CAPTURE
	std::string::size_type slash_pos = m_path.rfind('/');
	std::string::size_type qm_pos = m_path.rfind('?');
	std::string::size_type length =
		(qm_pos == std::string::npos) ?
		 std::string::npos : qm_pos - slash_pos - 1;

	if((slash_pos != std::string::npos) && (++slash_pos < m_path.size()))
	{
		n = m_path.substr(slash_pos, length);
	}
#endif // HAS_CAPTURE
	return n;
}

void k8s_handler::handle_error(const msg_data& data, const Json::Value& root, bool log)
{
	if(log)
	{
		log_error(data, root);
	}
}

void k8s_handler::log_error(const msg_data& data, const Json::Value& json)
{
#ifdef HAS_CAPTURE
	std::string unk_err = "Unknown.";
	std::ostringstream os;;
	os << "K8S server reported " << name() << " error for [" + uri(m_url).to_string(false) + m_path + "]: ";
	if(!json.isNull())
	{
		os << std::endl << json.toStyledString();
		unk_err.clear();
		m_error.reset(new k8s_api_error(data, json));
	}
	os << unk_err;
	g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
#endif // HAS_CAPTURE
}
#endif // CYGWING_AGENT
