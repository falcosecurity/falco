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
// k8s_event_handler.cpp
//
#ifndef CYGWING_AGENT

#include "k8s_event_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"

// filters normalize state and event JSONs, so they can be processed generically:
// event is turned into a single-entry array, state is turned into an array of ADDED events

std::string k8s_event_handler::EVENT_FILTER =
	"{"
	" type: .type,"
	" apiVersion: .object.apiVersion,"
	" kind: .object.kind,"
	" items:"
	" ["
	"  .object |"
	"  {"
	"   namespace: .metadata.namespace,"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   lastTimestamp: .lastTimestamp,"
	"   eventTime: .eventTime,"
	"   reason: .reason,"
	"   message: .message,"
	"   involvedObject: .involvedObject"
	"  }"
	" ]"
	"}";

std::string k8s_event_handler::STATE_FILTER =
	"{"
	" type: \"ADDED\","
	" apiVersion: .apiVersion,"
	" kind: \"Event\","
	" items:"
	" ["
	"  .items[] |"
	"  {"
	"   namespace: .metadata.namespace,"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   lastTimestamp: .lastTimestamp,"
	"   eventTime: .eventTime,"
	"   reason: .reason,"
	"   message: .message,"
	"   involvedObject: .involvedObject"
	"  }"
	" ]"
	"}";

k8s_event_handler::k8s_event_handler(k8s_state_t& state
#ifdef HAS_CAPTURE
	,ptr_t dependency_handler
	,collector_ptr_t collector
	,std::string url
	,const std::string& http_version
	,ssl_ptr_t ssl
	,bt_ptr_t bt
	,bool connect
	,bool blocking_socket
#endif // HAS_CAPTURE
	,filter_ptr_t event_filter):
		k8s_handler("k8s_event_handler", true,
#ifdef HAS_CAPTURE
					url, "/api/v1/events",
					STATE_FILTER, EVENT_FILTER, "", collector,
					http_version, 1000L, ssl, bt, true,
					connect, dependency_handler, blocking_socket,
#endif // HAS_CAPTURE
					~0, &state),
		m_event_filter(event_filter)
{
}

k8s_event_handler::~k8s_event_handler()
{
}

bool k8s_event_handler::handle_component(const Json::Value& json, const msg_data* data)
{
	if(m_event_filter)
	{
		if(m_state)
		{
			if(data)
			{
				if((data->m_reason == k8s_component::COMPONENT_ADDED) ||
				   (data->m_reason == k8s_component::COMPONENT_MODIFIED))
				{
					g_logger.log("K8s EVENT: handling event.", sinsp_logger::SEV_TRACE);
					const Json::Value& involved_object = json["involvedObject"];
					if(!involved_object.isNull())
					{
						bool is_aggregate = (get_json_string(json , "message").find("events with common reason combined") != std::string::npos);
						time_t last_ts = 0;
						time_t now_ts = get_epoch_utc_seconds_now();
						// So we first are going to check for "eventTime"
						// If that is empty, we will check for "lastTimestamp"
						// If that is also empty, use current timestamp and log it. 
						// This change is necessitated because in v1beta1/events, "EventTime" is
						// the main field that holds timestamp and `lastTimestamp` is deprecated.
						// This change is addressed towards that. 
						std::string evtTime = get_json_string(json, "eventTime");
						std::string ts = get_json_string(json , "lastTimestamp");
						if(!evtTime.empty())
						{
							last_ts	= get_epoch_utc_seconds(evtTime);
						}
						else if(!ts.empty())
						{
							last_ts = get_epoch_utc_seconds(ts);
						}
						else
						{
							// Ideally we should NEVER hit this case. But log it if we do, so we know.
							g_logger.log("K8s EVENT: both eventTime and lastTimestamp are null, using current timestamp. Event Json : " + Json::FastWriter().write(json) , sinsp_logger::SEV_INFO);
							last_ts = now_ts;
						}
						g_logger.log("K8s EVENT: lastTimestamp=" + std::to_string(last_ts) + ", now_ts=" + std::to_string(now_ts),
							     sinsp_logger::SEV_TRACE);
						if(((last_ts > 0) && (now_ts > 0)) && // we got good timestamps
						   !is_aggregate && // not an aggregated cached event
						   ((now_ts - last_ts) < 10)) // event not older than 10 seconds
						{
							const Json::Value& kind = involved_object["kind"];
							const Json::Value& event_reason = json["reason"];
							g_logger.log("K8s EVENT: involved object and event reason found:" + kind.asString() + '/' + event_reason.asString(),
										 sinsp_logger::SEV_TRACE);
							if(!kind.isNull() && kind.isConvertibleTo(Json::stringValue) &&
								!event_reason.isNull() && event_reason.isConvertibleTo(Json::stringValue))
							{
								bool is_allowed = m_event_filter->allows_all();
								std::string type = kind.asString();
								if(!is_allowed && !type.empty())
								{
									std::string reason = event_reason.asString();
									is_allowed = m_event_filter->allows_all(type);
									if(!is_allowed && !reason.empty())
									{
										is_allowed = m_event_filter->has(type, reason);
									}
								}
								if(is_allowed)
								{
									k8s_events& evts = m_state->get_events();
									if(evts.size() < sinsp_user_event::max_events_per_cycle())
									{
										k8s_event_t& evt = m_state->add_component<k8s_events, k8s_event_t>(evts,
																	data->m_name, data->m_uid, data->m_namespace);
										m_state->update_event(evt, json);
										m_event_limit_exceeded = false;
										if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
										{
											g_logger.log("K8s EVENT: added event [" + data->m_name + "]. "
														 "Queued events count=" + std::to_string(evts.size()), sinsp_logger::SEV_DEBUG);
										}
									}
									else if(!m_event_limit_exceeded) // only get in here once per cycle, to send event overflow warning
									{
										sinsp_user_event::emit_event_overflow("Kubernetes", get_machine_id());
										m_event_limit_exceeded = true;
										return false;
									}
									else // event limit exceeded and overflow logged, nothing to do
									{
										return false;
									}
								}
								else // event not allowed by filter, ignore
								{
									if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
									{
										g_logger.log("K8s EVENT: filter does not allow {\"" + type + "\", \"{" + event_reason.asString() + "\"} }",
												 sinsp_logger::SEV_TRACE);
										g_logger.log(m_event_filter->to_string(), sinsp_logger::SEV_TRACE);
									}
									m_event_ignored = true;
									return false;
								}
							}
							else
							{
								g_logger.log("K8s EVENT: event type or involvedObject kind not found.", sinsp_logger::SEV_ERROR);
								if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
								{
									g_logger.log(Json::FastWriter().write(json), sinsp_logger::SEV_TRACE);
								}
								return false;
							}
						}
						else // old event, ignore
						{
							g_logger.log("K8s EVENT: old event, ignoring: "
										 ", lastTimestamp=" + std::to_string(last_ts) + ", now_ts=" + std::to_string(now_ts),
										sinsp_logger::SEV_DEBUG);
							m_event_ignored = true;
							return false;
						}
					}
					else
					{
						g_logger.log("K8s EVENT: involvedObject not found.", sinsp_logger::SEV_ERROR);
						g_logger.log(Json::FastWriter().write(json), sinsp_logger::SEV_TRACE);
						return false;
					}
				}
				else // not ADDED or MODIFIED event, ignore
				{
					m_event_ignored = true;
					return false;
				}
			}
			else
			{
				g_logger.log("K8s EVENT: msg data is null.", sinsp_logger::SEV_ERROR);
				g_logger.log(Json::FastWriter().write(json), sinsp_logger::SEV_TRACE);
				return false;
			}
		}
		else
		{
			g_logger.log("K8s EVENT: state is null.", sinsp_logger::SEV_ERROR);
			return false;
		}
	}
	else
	{
		g_logger.log("K8s EVENT: no filter, K8s events disabled.", sinsp_logger::SEV_TRACE);
		return false;
	}
	return true;
}

void k8s_event_handler::handle_json(Json::Value&& root)
{
	/*if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
	{
		g_logger.log(json_as_string(root), sinsp_logger::SEV_TRACE);
	}*/

	if(!m_state)
	{
		throw sinsp_exception("k8s_handler (" + get_id() + "), state is null for " + get_url() + ").");
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
						std::string reason_type = data.get_reason_desc();
						if(data.m_reason != k8s_component::COMPONENT_ADDED &&
							data.m_reason != k8s_component::COMPONENT_MODIFIED &&
							data.m_reason != k8s_component::COMPONENT_DELETED &&
							data.m_reason != k8s_component::COMPONENT_NONEXISTENT &&
							data.m_reason != k8s_component::COMPONENT_ERROR)
						{
							g_logger.log(std::string("Unsupported K8S " + name() + " event reason: ") +
										 std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
							continue;
						}
						/*if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
						{
							g_logger.log("K8s handling event:\n" + json_as_string(item), sinsp_logger::SEV_TRACE);
						}*/
						if(handle_component(item, &data))
						{
							std::ostringstream os;
							os << "K8s [" + reason_type + ", " << data.m_kind <<
								", " << data.m_name << ", " << data.m_uid << "]";
							g_logger.log(os.str(), sinsp_logger::SEV_INFO);
						}
						else if(!m_event_ignored)
						{
							g_logger.log("K8s: error occurred while handling " + reason_type +
										 " event for " + data.m_kind + ' ' + data.m_name + " [" +
										 data.m_uid + ']', sinsp_logger::SEV_ERROR);
						}
						m_event_ignored = false;
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
#endif // CYGWING_AGENT
