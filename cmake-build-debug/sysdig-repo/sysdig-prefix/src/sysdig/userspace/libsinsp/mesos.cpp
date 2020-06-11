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
// mesos.cpp
//
#ifndef CYGWING_AGENT

#include "mesos.h"
#include "mesos_component.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "json_error_log.h"

const mesos_component::component_map mesos::m_components =
{
	{ mesos_component::MESOS_FRAMEWORK, "framework" },
	{ mesos_component::MESOS_TASK,      "task"      },
	{ mesos_component::MESOS_SLAVE,     "slave"     }
};

const std::string mesos::default_state_uri    = "http://localhost:5050";
const std::string mesos::default_state_api    = "/master/state.json";
const std::string mesos::default_marathon_uri = "http://localhost:8080";
const std::string mesos::default_groups_api   = "/v2/groups";
const std::string mesos::default_apps_api     = "/v2/apps?embed=apps.tasks";
const std::string mesos::default_watch_api    = "/v2/events";
const std::string mesos::default_version_api  = "/version";
const int mesos::default_timeout_ms           = 5000;

mesos::mesos(const std::string& mesos_state_json,
			 const std::string& marathon_groups_json,
			 const std::string& marathon_apps_json):
				m_discover_mesos_leader(false),
				m_discover_marathon_uris(false),
				m_testing(true)
{
	if(mesos_state_json.empty() ||
	   (marathon_groups_json.empty() && !marathon_apps_json.empty()) ||
	   (!marathon_groups_json.empty() && marathon_apps_json.empty()))
	{
		throw sinsp_exception("Mesos state AND (both OR none [marathon apps and groups]) are needed");
	}
	mesos_http::json_ptr_t state_json = mesos_http::try_parse(mesos_state_json, "fixed-mesos-state");
	if(state_json)
	{
		set_state_json(state_json);
		if(!marathon_groups_json.empty())
		{
			const Json::Value& frameworks = (*state_json)["frameworks"];
			if(frameworks.isNull() || !frameworks.isArray())
			{
				throw sinsp_exception("Unexpected condition while detecting Mesos master: frameworks entry not found.");
			}
			g_logger.log("Found " + std::to_string(frameworks.size()) + " Mesos frameworks", sinsp_logger::SEV_DEBUG);
			std::string framework_id;
			for(auto framework : frameworks)
			{
				const Json::Value& name = framework["name"];
				if(!name.isNull() && name.isConvertibleTo(Json::stringValue) &&  mesos_framework::is_root_marathon(name.asString()))
				{
					const Json::Value& id = framework["id"];
					if(!id.isNull() && id.isConvertibleTo(Json::stringValue))
					{
						framework_id = id.asString();
					}
				}
			}
			mesos_http::json_ptr_t dummy_group;
			set_marathon_groups_json(mesos_http::try_parse(marathon_groups_json, "fixed-marathon-state"), framework_id);
			set_marathon_apps_json(dummy_group/*mesos_http::try_parse(marathon_apps_json, "fixed-groups-state")*/, framework_id);
		}
		collect_data();
	}
	else
	{
		throw sinsp_exception("Could not create Mesos state JSON.");
	}
}

mesos::mesos(const std::string& state_uri,
	const uri_list_t& marathon_uris,
	bool discover_mesos_leader,
	bool discover_marathon_leader,
	const credentials_t& mesos_credentials,
	const credentials_t& marathon_credentials,
	int timeout_ms,
	bool is_captured,
	bool verbose):
#ifdef HAS_CAPTURE
		m_collector(false),
		m_mesos_uri(state_uri),
		m_marathon_uris(marathon_uris),
#endif // HAS_CAPTURE
		m_state(is_captured, verbose),
		m_discover_mesos_leader(discover_mesos_leader),
		m_discover_marathon_uris(discover_marathon_leader || marathon_uris.empty()),
		m_timeout_ms(timeout_ms),
		m_verbose(verbose),
		m_testing(false)
{
#ifdef HAS_CAPTURE
	g_logger.log(std::string("Creating Mesos object for [" +
							 (m_mesos_uri.empty() ? std::string("capture replay") : m_mesos_uri)  +
							 "], failover autodiscovery set to ") +
							(m_discover_mesos_leader ? "true" : "false"),
				 sinsp_logger::SEV_DEBUG);

	if(m_marathon_uris.size() > 1)
	{
		std::string marathon_uri = m_marathon_uris[0];
		m_marathon_uris.clear();
		m_marathon_uris.emplace_back(marathon_uri);
		g_logger.log("Multiple root marathon URIs configured; only the first one (" + marathon_uri + ") will have effect;"
					" others will be treated as generic frameworks (user Marathon frameworks will be discovered).", sinsp_logger::SEV_WARNING);
	}
	uri mesos_state_uri(state_uri);
	mesos_state_uri.get_credentials(m_mesos_credentials);
	if(m_marathon_uris.size())
	{
		uri marathon_uri(m_marathon_uris[0]);
		marathon_uri.get_credentials(m_marathon_credentials);
	}

	// explicitly specified credentials trump the ones in URI
	if(!mesos_credentials.first.empty())
	{
		m_mesos_credentials.first = mesos_credentials.first;
		m_mesos_credentials.second = mesos_credentials.second;
	}
	if(!marathon_credentials.first.empty())
	{
		m_marathon_credentials.first = marathon_credentials.first;
		m_marathon_credentials.second = marathon_credentials.second;
	}

#endif
	init();
}

mesos::mesos(const std::string& state_uri,
	const uri_list_t& marathon_uris,
	bool discover_mesos_leader,
	bool discover_marathon_leader,
	const credentials_t& dcos_enterprise_credentials,
	int timeout_ms,
	bool is_captured,
	bool verbose):
	mesos_auth(dcos_enterprise_credentials),
#ifdef HAS_CAPTURE
		m_collector(false),
		m_mesos_uri(state_uri),
		m_marathon_uris(marathon_uris),
#endif // HAS_CAPTURE
		m_state(is_captured, verbose),
		m_discover_mesos_leader(discover_mesos_leader),
		m_discover_marathon_uris(discover_marathon_leader || marathon_uris.empty()),
		m_timeout_ms(timeout_ms),
		m_verbose(verbose),
		m_testing(false)
{
#ifdef HAS_CAPTURE
	g_logger.log(std::string("Creating Mesos object for [" +
							 (m_mesos_uri.empty() ? std::string("capture replay") : m_mesos_uri)  +
							 "], failover autodiscovery set to ") +
							(m_discover_mesos_leader ? "true" : "false"),
				 sinsp_logger::SEV_DEBUG);

	if(m_marathon_uris.size() > 1)
	{
		std::string marathon_uri = m_marathon_uris[0];
		m_marathon_uris.clear();
		m_marathon_uris.emplace_back(marathon_uri);
		g_logger.log("Multiple root marathon URIs configured; only the first one (" + marathon_uri + ") will have effect;"
					" others will be treated as generic frameworks (user Marathon frameworks will be discovered).", sinsp_logger::SEV_WARNING);
	}

#endif
	init();
}

mesos::~mesos()
{
}

void mesos::init()
{
#ifdef HAS_CAPTURE
	if(!m_mesos_uri.empty())
	{
		m_collector.remove_all();
		if((m_state_http) && (!m_state_http.unique()))
		{
			throw sinsp_exception("Invalid access to Mesos initializer: mesos state http client for [" +
								 m_mesos_uri + "] not unique.");
		}
		m_state_http = std::make_shared<mesos_http>(*this, m_mesos_uri + default_state_api, m_discover_mesos_leader, m_marathon_uris.empty(), m_timeout_ms, m_token);
		rebuild_mesos_state(true);
		if(!has_marathon())
		{
			init_marathon();
		}
	}
#endif // HAS_CAPTURE
}

void mesos::init_marathon()
{
#ifdef HAS_CAPTURE
	if(!m_mesos_uri.empty())
	{
		m_marathon_groups_http.clear();
		m_marathon_apps_http.clear();

		const uri_list_t& marathons = m_discover_marathon_uris ? m_state_http->get_marathon_uris() : m_marathon_uris;
		if(marathons.size())
		{
			g_logger.log("Found " + std::to_string(marathons.size()) + " Marathon URIs", sinsp_logger::SEV_DEBUG);
			for(const auto& muri : marathons)
			{
				g_logger.log("Creating Marathon http objects: " + uri(muri).to_string(false), sinsp_logger::SEV_DEBUG);
				m_marathon_groups_http[muri] = std::make_shared<marathon_http>(*this, muri + default_groups_api, m_discover_marathon_uris, m_timeout_ms, m_token);
				m_marathon_apps_http[muri]   = std::make_shared<marathon_http>(*this, muri + default_apps_api, m_discover_marathon_uris, m_timeout_ms, m_token);
			}

			if(has_marathon())
			{
				rebuild_marathon_state(true);
			}
		}
	}
#endif // HAS_CAPTURE
}

void mesos::refresh_token()
{
#ifdef HAS_CAPTURE
	mesos_auth::refresh_token();
	m_state_http->set_token(m_token);
	if(has_marathon())
	{
		for(auto& group_http : m_marathon_groups_http)
		{
			if(group_http.second)
			{
				group_http.second->set_token(m_token);
			}
			else
			{
				throw sinsp_exception("Marathon groups HTTP client is null.");
			}
		}
		for(auto& app_http : m_marathon_apps_http)
		{
			if(app_http.second)
			{
				app_http.second->set_token(m_token);
			}
			else
			{
				throw sinsp_exception("Marathon apps HTTP client is null.");
			}
		}
	}
#endif // HAS_CAPTURE
}

#ifdef HAS_CAPTURE
const mesos::uri_list_t &mesos::marathon_uris()
{
	return (m_discover_marathon_uris ? m_state_http->get_marathon_uris() : m_marathon_uris);
}
#endif

void mesos::refresh()
{
	rebuild_mesos_state();
	if(has_marathon())
	{
		rebuild_marathon_state();
	}
}

void mesos::rebuild_mesos_state(bool full)
{
#ifdef HAS_CAPTURE
	if(!m_mesos_uri.empty())
	{
		if(full)
		{
			clear_mesos();
			if(m_state_http)
			{
				m_state_http->get_all_data(&mesos::parse_state);
			}
			else
			{
				throw sinsp_exception("Mesos state HTTP client is null.");
			}
		}
		else
		{
			connect_mesos();
			send_mesos_data_request();
			collect_data();
		}
	}
#endif // HAS_CAPTURE
}

void mesos::rebuild_marathon_state(bool full)
{
#ifdef HAS_CAPTURE
	if(has_marathon())
	{
		if(full)
		{
			clear_marathon();

			for(auto& group_http : m_marathon_groups_http)
			{
				if(group_http.second)
				{
					group_http.second->get_all_data(&mesos::parse_groups);
				}
				else
				{
					throw sinsp_exception("Marathon groups HTTP client is null.");
				}
			}

			for(auto& app_http : m_marathon_apps_http)
			{
				if(app_http.second)
				{
					app_http.second->get_all_data(&mesos::parse_apps);
				}
				else
				{
					throw sinsp_exception("Marathon apps HTTP client is null.");
				}
			}
		}
		else
		{
			connect_marathon();
			send_marathon_data_request();
			collect_data();
		}
		if(m_state_http)
		{
			const mesos_http::marathon_uri_t& marathon_uris = m_marathon_uris.empty() ?
															  m_state_http->get_marathon_uris() :
															  m_marathon_uris;
			if(marathon_uris.size())
			{
				m_state.set_marathon_uri(marathon_uris[0]);
			}
			else
			{
				throw sinsp_exception("Marathon detected but Marathon URI not found.");
			}
		}
		else
		{
			throw sinsp_exception("Mesos state HTTP client is null.");
		}
	}
#endif // HAS_CAPTURE
}

#ifdef HAS_CAPTURE
void mesos::send_marathon_data_request()
{
	if(has_marathon())
	{
		for(auto& group_http : m_marathon_groups_http)
		{
			if(group_http.second)
			{
				group_http.second->send_request();
				g_logger.log("Marathon groups request sent.", sinsp_logger::SEV_DEBUG);
			}
			else
			{
				throw sinsp_exception("Marathon groups HTTP client is null.");
			}
		}
		for(auto& app_http : m_marathon_apps_http)
		{
			if(app_http.second)
			{
				app_http.second->send_request();
				g_logger.log("Marathon apps request sent.", sinsp_logger::SEV_DEBUG);
			}
			else
			{
				throw sinsp_exception("Marathon apps HTTP client is null.");
			}
		}
	}
}

void mesos::connect_marathon()
{
	if(has_marathon())
	{
		for(auto& group_http : m_marathon_groups_http)
		{
			if(!connect(group_http.second, &mesos::set_marathon_groups_json, 2))
			{
				throw sinsp_exception("Connection to Marathon group API failed.");
			}
		}
		for(auto& app_http : m_marathon_apps_http)
		{
			if(!connect(app_http.second, &mesos::set_marathon_apps_json, 3))
			{
				throw sinsp_exception("Connection to Marathon app API failed.");
			}
		}
	}
}

void mesos::send_mesos_data_request()
{
	if(m_state_http)
	{
		m_state_http->send_request();
	}
	else
	{
		throw sinsp_exception("Mesos state HTTP client is null.");
	}
}

void mesos::connect_mesos()
{
	if(!connect(m_state_http, &mesos::set_state_json, 1))
	{
		throw sinsp_exception("Connection to Mesos API failed.");
	}
}
#endif // HAS_CAPTURE

bool mesos::is_alive() const
{
#ifdef HAS_CAPTURE
	if(m_state_http && !m_state_http->is_connected())
	{
		g_logger.log("Mesos state connection loss.", sinsp_logger::SEV_WARNING);
		return false;
	}

	for(const auto& group : m_marathon_groups_http)
	{
		if(group.second && !group.second->is_connected())
		{
			g_logger.log("Marathon groups connection loss.", sinsp_logger::SEV_WARNING);
			return false;
		}
	}

	for(const auto& app : m_marathon_apps_http)
	{
		if(app.second && !app.second->is_connected())
		{
			g_logger.log("Marathon apps connection loss.", sinsp_logger::SEV_WARNING);
			return false;
		}
	}
#endif // HAS_CAPTURE
	return true;
}

#ifdef HAS_CAPTURE

void mesos::check_collector_status(int expected)
{
	if(!m_collector.is_healthy(expected))
	{
		throw sinsp_exception("Mesos collector not healthy (has " + std::to_string(m_collector.subscription_count()) +
							  " connections, expected " + std::to_string(expected) + "); giving up on data collection in this cycle ...");
	}
}

void mesos::send_data_request(bool collect)
{
	if(m_mesos_state_json && !m_mesos_state_json->isNull()) { return; }
	connect_mesos();
	send_mesos_data_request();
	g_logger.log("Mesos request sent.", sinsp_logger::SEV_DEBUG);

	if(has_marathon())
	{
		for(auto& group : m_marathon_groups_json)
		{
			if(group.second && !group.second->isNull()) { return; }
		}
		for(auto& app : m_marathon_apps_json)
		{
			if(app.second && !app.second->isNull()) { return; }
		}
		connect_marathon();
		send_marathon_data_request();
	}

	if(collect) { collect_data(); }
}

void mesos::capture_frameworks(const Json::Value& root, Json::Value& capture)
{
	const Json::Value& frameworks = root["frameworks"];
	if(!frameworks.isNull())
	{
		if(frameworks.isArray())
		{
			if(frameworks.size())
			{
				capture["frameworks"] = Json::arrayValue;
				for(const auto& framework : frameworks)
				{
					Json::Value c_framework;
					c_framework["active"] = framework["active"];
					c_framework["id"] = framework["id"];
					c_framework["name"] = framework["name"];
					c_framework["hostname"] = framework["hostname"];
					c_framework["webui_url"] = framework["webui_url"];
					c_framework["tasks"] = Json::arrayValue;
					Json::Value& c_tasks = c_framework["tasks"];
					for(const auto& task : framework["tasks"])
					{
						Json::Value& c_task = c_tasks.append(Json::Value());
						c_task["id"] = task["id"];
						c_task["name"] = task["name"];
						c_task["framework_id"] = task["framework_id"];
						c_task["executor_id"] = task["executor_id"];
						c_task["slave_id"] = task["slave_id"];
						c_task["state"] = task["state"];
						//? TODO: statuses
						c_task["labels"] = task["labels"];
					}
					capture["frameworks"].append(c_framework);
				}
			}
		}
	}
}

void mesos::capture_slaves(const Json::Value& root, Json::Value& capture)
{
	const Json::Value& slaves = root["slaves"];
	if(!slaves.isNull())
	{
		capture["slaves"] = Json::arrayValue;
		for(const auto& slave : slaves)
		{
			Json::Value c_slave;
			c_slave["hostname"] = slave["hostname"];
			c_slave["id"] = slave["id"];
			capture["slaves"].append(c_slave);
		}
	}
}
#endif // HAS_CAPTURE

bool mesos::collect_data()
{
#ifdef HAS_CAPTURE
	const int tout_s = 30;

	//TODO: see if we can do better here - instead of timing out, depending on
	//      mesos_collector socket drop detection when remote end closes connection
	time_t now; time(&now);
	if(m_last_mesos_refresh && difftime(now, m_last_mesos_refresh) > tout_s)
	{
		throw sinsp_exception("Detected stalled Mesos connection (" +
							  std::to_string(difftime(now, m_last_mesos_refresh)) + "s)."
							  " Reconnect attempt in next cycle ...");
	}
	if(m_last_marathon_refresh && difftime(now, m_last_marathon_refresh) > tout_s)
	{
		throw sinsp_exception("Detected stalled Marathon connection(" +
							  std::to_string(difftime(now, m_last_marathon_refresh)) + "s)."
							  " Reconnect attempt in next cycle ...");
	}
	if(m_json_error)
	{
		throw sinsp_exception("Detected JSON parsing error. Reconnect attempt in next cycle ...");
	}

	bool ret = false;
	if(m_collector.subscription_count())
	{
		m_collector.get_data();
	}

	if(m_mesos_state_json && !m_mesos_state_json->isNull())
	{
		g_logger.log("Mesos state data detected.", sinsp_logger::SEV_DEBUG);
		if(has_marathon())
		{
			g_logger.log("Marathon connection detected.", sinsp_logger::SEV_DEBUG);
			if(!m_marathon_apps_json.empty() && !m_marathon_groups_json.empty())
			{
				g_logger.log("Marathon data detected.", sinsp_logger::SEV_DEBUG);
				for(auto& group : m_marathon_groups_json)
				{
					if(group.second && !group.second->isNull())
					{
						json_map_type_t::iterator app_it = m_marathon_apps_json.find(group.first);
						if(app_it != m_marathon_apps_json.end())
						{
							if(app_it->second && !app_it->second->isNull())
							{
								parse_state(std::move(*m_mesos_state_json));
								m_mesos_state_json.reset();
								m_last_mesos_refresh = now;
								if(m_inactive_frameworks.size())
								{
									g_logger.log("Collection detected " + std::to_string(m_inactive_frameworks.size()) + " inactive frameworks",
												 sinsp_logger::SEV_DEBUG);
								}
								if(m_inactive_frameworks.find(group.first) == m_inactive_frameworks.end())
								{
									g_logger.log("Detected active Marathon framework " + group.first, sinsp_logger::SEV_DEBUG);
									// +++ order is important - apps belong to groups and must be processed after
									parse_groups(std::move(*group.second), group.first);
									parse_apps(std::move(*app_it->second), app_it->first);
									m_last_marathon_refresh = now;
									// ---
								}
								else // framework was shut down, clear groups/apps
								{
									g_logger.log("Detected inactive Marathon framework " + group.first, sinsp_logger::SEV_DEBUG);
									m_state.erase_groups(group.first); // apps will go away with groups
									m_inactive_frameworks.insert(group.first);
								}
								group.second.reset();
								app_it->second.reset();
								m_json_error = false;
								ret = true;
							}
							else if((difftime(now, m_last_marathon_refresh) > tout_s) || m_json_error)
							{
								std::string errstr = "Detected null Marathon app (" + app_it->first + "), resetting current state.";
								g_logger.log(errstr, sinsp_logger::SEV_WARNING);
								g_json_error_log.log(app_it->first, errstr, sinsp_utils::get_current_time_ns(), "marathon-apps-state");
								m_mesos_state_json.reset();
								group.second.reset();
								app_it->second.reset();
								m_json_error = false;
							}
						}
						else
						{
							// must never happen
							throw sinsp_exception("A discrepancy found between groups and apps "
												  "(app json for framework [" + group.first + "] not found in json map).");
						}
					}
					else if((difftime(now, m_last_marathon_refresh) > tout_s) || m_json_error)
					{
						g_logger.log("Detected null Marathon group (" + group.first + "), resetting current state.", sinsp_logger::SEV_WARNING);
						m_mesos_state_json.reset();
						json_map_type_t::iterator app_it = m_marathon_apps_json.find(group.first);
						if(app_it != m_marathon_apps_json.end())
						{
							app_it->second.reset();
						}
						m_json_error = false;
					}
				}
			}
		}
		else
		{
			parse_state(std::move(*m_mesos_state_json));
			m_mesos_state_json.reset();
			m_marathon_groups_json.clear();
			m_marathon_apps_json.clear();
			if(m_state_http->get_marathon_uris().size())
			{
				rebuild_marathon_state(true);
			}
			m_json_error = false;
			ret = true;
		}
	}

	return ret;
#else
	return true;
#endif // HAS_CAPTURE
}

void mesos::handle_frameworks(const Json::Value& root)
{
	const Json::Value& frameworks = root["frameworks"];
	if(!frameworks.isNull())
	{
		if(frameworks.isArray())
		{
			if(frameworks.size())
			{
				for(const auto& framework : frameworks)
				{
					const Json::Value& uid = framework["id"];
					if(!uid.isNull() && uid.isString())
					{
						const Json::Value& fw_name = framework["name"];
						std::string name;
						if(!fw_name.isNull() && fw_name.isString())
						{
							name = framework["name"].asString();
						}
						if(!mesos_framework::is_framework_active(framework))
						{
							framework_list_t::iterator it = m_inactive_frameworks.find(uid.asString());
							if(it == m_inactive_frameworks.end())
							{
								std::string fid = uid.asString();
								m_inactive_frameworks.insert(fid);
								m_activated_frameworks.erase(fid);
								g_logger.log("Mesos framework deactivated: " + name + '[' + fid + ']', sinsp_logger::SEV_INFO);
								remove_framework(framework);
#ifdef HAS_CAPTURE
								remove_framework_http(m_marathon_groups_http, fid);
								remove_framework_http(m_marathon_apps_http, fid);
#endif // HAS_CAPTURE
							}
						}
						else // active framework detected
						{
							add_framework(framework);
							if((m_inactive_frameworks.erase(uid.asString())) ||
							   (m_activated_frameworks.find(uid.asString()) == m_activated_frameworks.end()))
							{
								g_logger.log("New or activated Mesos framework detected: " + name + " [" + uid.asString() + ']', sinsp_logger::SEV_INFO);
								m_activated_frameworks.insert(uid.asString());
#ifdef HAS_CAPTURE
								if(mesos_framework::is_root_marathon(name) &&
									find_if(m_marathon_groups_http.begin(), m_marathon_groups_http.end(), [uid](const decltype(m_marathon_groups_http)::value_type& item)
									{
										return item.second->get_framework_id() == uid.asString();
									}) == m_marathon_groups_http.end())
								{
									init_marathon();
								}
#endif
							}
						}
					}
				}
			}
			else
			{
				throw sinsp_exception("No Mesos frameworks found (possibly Mesos master HA migration, will retry).");
			}
		}
		else
		{
			throw sinsp_exception("Mesos frameworks entry found but not a JSON array.");
		}
	}
	else
	{
		throw sinsp_exception("No Mesos frameworks entry found in state.");
	}
}

void mesos::handle_slaves(const Json::Value& root)
{
	const Json::Value& slaves = root["slaves"];
	if(!slaves.isNull())
	{
		for(const auto& slave : slaves)
		{
			add_slave(slave);
		}
	}
	else
	{
		g_logger.log("No frameworks found.", sinsp_logger::SEV_WARNING);
	}
}

void mesos::add_framework(const Json::Value& framework)
{
	std::string name, uid;
	const Json::Value& fname = framework["name"];
	const Json::Value& fid = framework["id"];
	if(!fname.isNull())
	{
		name = fname.asString();
	}
	if(!fid.isNull())
	{
		uid = fid.asString();
	}
	if(!m_creation_logged)
	{
		std::ostringstream os;
		os << "Adding Mesos framework: [" << name << ',' << uid << ']';
		g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
	}
	m_state.emplace_framework(mesos_framework(name, uid));
	add_tasks(m_state.get_frameworks().back(), framework);
}

void mesos::remove_framework(const Json::Value& framework)
{
	m_state.remove_framework(framework);
}

#ifdef HAS_CAPTURE
void mesos::remove_framework_http(marathon_http_map& http_map, const std::string& framework_id)
{
	for(marathon_http_map::iterator it = http_map.begin(), end = http_map.end(); it != end; ++it)
	{
		if(it->second && it->second->get_framework_id() == framework_id)
		{
			http_map.erase(it);
			g_logger.log("Removed http for deactivated Marathon framework [" + framework_id + ']',
						 sinsp_logger::SEV_DEBUG);
			return;
		}
	}
}
#endif // HAS_CAPTURE

void mesos::add_slave(const Json::Value& slave)
{
	std::string name, uid;
	const Json::Value& sname = slave["hostname"];
	const Json::Value& sid = slave["id"];
	if(!sname.isNull())
	{
		name = sname.asString();
	}
	if(!sid.isNull())
	{
		uid = sid.asString();
	}
	if(!m_creation_logged)
	{
		std::ostringstream os;
		os << "Adding Mesos slave: [" << name << ',' << uid << ']';
		g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
	}
	m_state.emplace_slave(mesos_slave(name, uid));
}

void mesos::add_tasks_impl(mesos_framework& framework, const Json::Value& tasks)
{
	if(!tasks.isNull())
	{
		for(const auto& task : tasks)
		{
			if(mesos_task::is_task_running(task))
			{
				mesos_task::ptr_t t = mesos_task::make_task(task);
				std::ostringstream os;
				if(t)
				{
					os << "Adding Mesos task: [" << framework.get_name() << ':' << t->get_name() << ',' << t->get_uid() << ']';
					g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
					m_state.add_or_replace_task(framework, t);
				}
				else
				{
					std::string name, uid, sid;
					Json::Value fname = task["name"];
					if(!fname.isNull()) { name = fname.asString(); }
					Json::Value fid = task["id"];
					if(!fid.isNull()) { uid = fid.asString(); }
					Json::Value fsid = task["slave_id"];
					if(!fsid.isNull()) { sid = fsid.asString(); }
					os << "Failed to add Mesos task: [" << framework.get_name() << ':' << name << ',' << uid << "], running on slave " << sid;
					g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
					g_json_error_log.log(framework.get_name(), os.str(), sinsp_utils::get_current_time_ns(), "add_tasks_impl");
				}
			}
		}
	}
	else
	{
		std::string errstr = "Tasks is null";
		g_logger.log(errstr, sinsp_logger::SEV_ERROR);
		g_json_error_log.log(framework.get_name(), errstr, sinsp_utils::get_current_time_ns(), "add_tasks_impl for framework");
	}
}

void mesos::add_tasks(mesos_framework& framework, const Json::Value& f_val)
{
	const Json::Value& tasks = f_val["tasks"];
	add_tasks_impl(framework, tasks);
}

void mesos::check_frameworks(const json_ptr_t& json)
{
	if(has_marathon() && json && !json->isNull())
	{
		const Json::Value& frameworks = (*json)["frameworks"];
		if(frameworks.isNull())
		{
			throw sinsp_exception("No Mesos frameworks entry found.");
		}
		else
		{
			if(frameworks.isArray())
			{
				if(!frameworks.size())
				{
					throw sinsp_exception("No Mesos frameworks found (possibly Mesos master HA migration).");
				}
			}
			else
			{
				throw sinsp_exception("Unexpected Mesos frameworks entry found (not an array).");
			}
		}
	}
}

void mesos::set_state_json(json_ptr_t json, const std::string&)
{
	bool json_error = !json || (json && json->isNull());
	m_mesos_state_json = json;
	if(!json_error)
	{
		g_logger.log("Received state JSON", sinsp_logger::SEV_DEBUG);
		check_frameworks(m_mesos_state_json);
	}
	else
	{
		g_logger.log("Received invalid state JSON", sinsp_logger::SEV_WARNING);
	}
	m_json_error = m_json_error || json_error;
}

void mesos::parse_state(Json::Value&& root)
{
	clear_mesos();
	handle_frameworks(root);
	handle_slaves(root);
#ifdef HAS_CAPTURE
	if(m_state.is_captured())
	{
		Json::Value capt;
		capture_frameworks(root, capt);
		capture_slaves(root, capt);
		m_state.enqueue_capture_event(mesos_state_t::capture::MESOS_STATE, Json::FastWriter().write(capt));
	}
#endif // HAS_CAPTURE
	if(m_verbose)
	{
		std::cout << Json::FastWriter().write(root) << std::endl;
	}
	if(!m_creation_logged)
	{
		m_creation_logged = true;
	}
}

void mesos::parse_state(json_ptr_t json, const std::string&)
{
	if(json && !json->isNull())
	{
		parse_state(std::move(*json));
	}
	else
	{
		throw sinsp_exception("Invalid JSON (parsing Mesos state failed).");
	}
}

void mesos::set_marathon_groups_json(json_ptr_t json, const std::string& framework_id)
{
	bool json_error = !json || (json && json->isNull());
	m_marathon_groups_json[framework_id] = json;
	if(!json_error)
	{
		g_logger.log("Received groups JSON for Marathon framework [" + framework_id + ']', sinsp_logger::SEV_DEBUG);
	}
	else
	{
		g_logger.log("Received invalid Marathon groups JSON", sinsp_logger::SEV_WARNING);
	}
	m_json_error = m_json_error || json_error;
}

void mesos::set_marathon_apps_json(json_ptr_t json, const std::string& framework_id)
{
	bool json_error = !json || (json && json->isNull());
	m_marathon_apps_json[framework_id] = json;
	if(!json_error)
	{
		g_logger.log("Received apps JSON for Marathon framework [" + framework_id + ']', sinsp_logger::SEV_DEBUG);
	}
	else
	{
		std::string errstr = "Received invalid Marathon apps JSON";
		g_logger.log(errstr, sinsp_logger::SEV_WARNING);
		g_json_error_log.log("(null)", errstr, sinsp_utils::get_current_time_ns(), "set-marathon-apps-json");
	}
	m_json_error = m_json_error || json_error;
}

void mesos::simulate_event(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root))
	{
		Json::Value::Members members = root.getMemberNames();
		for (auto& member : members)
		{
			if(member == "mesos_state")
			{
				m_discover_marathon_uris = false;
				parse_state(std::move(root[member]));
			}
			else if(member == "marathon_groups")
			{
				const Json::Value& frameworkId = root[member]["frameworkId"];
				if(!frameworkId.isNull() && frameworkId.isString())
				{
					m_state.parse_groups(std::move(root[member]), frameworkId.asString());
				}
				else
				{
					throw sinsp_exception("Framework ID for Marathon groups not found during event simulation.");
				}
			}
			else if(member == "marathon_apps")
			{
				const Json::Value& frameworkId = root[member]["frameworkId"];
				if(!frameworkId.isNull() && frameworkId.isString())
				{
					m_state.parse_apps(std::move(root[member]), frameworkId.asString());
				}
				else
				{
					throw sinsp_exception("Framework ID for Marathon groups not found during event simulation.");
				}
			}
		}
	}
	else
	{
		std::string errstr = "Could not parse json (" + reader.getFormattedErrorMessages() + ")";
		g_logger.log(errstr, sinsp_logger::SEV_ERROR);
		g_json_error_log.log(json, errstr, sinsp_utils::get_current_time_ns(), "parse-mesos-evt");
	}
}
#endif // CYGWING_AGENT
