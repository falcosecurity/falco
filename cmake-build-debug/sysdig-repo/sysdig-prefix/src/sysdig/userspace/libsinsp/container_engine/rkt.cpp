/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

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

#include "container_engine/rkt.h"

#include <unistd.h>

#include "sinsp.h"
#include "sinsp_int.h"

using namespace libsinsp::container_engine;

bool rkt::match(container_cache_interface *cache, sinsp_threadinfo *tinfo, sinsp_container_info& container_info, string& rkt_podid, string& rkt_appname, bool query_os_for_missing_info)
{
	for(auto it = tinfo->m_cgroups.begin(); it != tinfo->m_cgroups.end(); ++it)
	{
		string cgroup = it->second;

		static const string COREOS_PODID_VAR = "container_uuid=";
		static const string SYSTEMD_UUID_ARG = "--uuid=";
		static const string SERVICE_SUFFIX = ".service";
		if(cgroup.rfind(SERVICE_SUFFIX) == cgroup.size() - SERVICE_SUFFIX.size())
		{
			// check if there is a parent with pod uuid var
			sinsp_threadinfo::visitor_func_t visitor = [&](sinsp_threadinfo* ptinfo)
			{
				for(const auto& env_var : ptinfo->get_env())
				{
					auto container_uuid_pos = env_var.find(COREOS_PODID_VAR);
					if(container_uuid_pos == 0)
					{
						rkt_podid = env_var.substr(COREOS_PODID_VAR.size());
						return false;
					}
				}
				for(const auto& arg : ptinfo->m_args)
				{
					if(arg.find(SYSTEMD_UUID_ARG) != string::npos)
					{
						rkt_podid = arg.substr(SYSTEMD_UUID_ARG.size());
						return false;
					}
				}
				return true;
			};
			tinfo->traverse_parent_state(visitor);

			if(!rkt_podid.empty())
			{
				auto last_slash = cgroup.find_last_of("/");
				rkt_appname = cgroup.substr(last_slash + 1, cgroup.size() - last_slash - SERVICE_SUFFIX.size() - 1);

				char image_manifest_path[SCAP_MAX_PATH_SIZE];
				snprintf(image_manifest_path, sizeof(image_manifest_path), "%s/var/lib/rkt/pods/run/%s/appsinfo/%s/manifest", scap_get_host_root(), rkt_podid.c_str(), rkt_appname.c_str());

				// First lookup if the container exists in our table, otherwise only if we are live check if it has
				// an entry in /var/lib/rkt. In capture mode only the former will be used.
				// In live mode former will be used only if we already hit that container
				bool is_rkt_pod_id_valid = cache->container_exists(rkt_podid + ":" + rkt_appname); // if it's already on our table
#ifdef HAS_CAPTURE
				if(!is_rkt_pod_id_valid && query_os_for_missing_info)
				{
					is_rkt_pod_id_valid = (access(image_manifest_path, F_OK) == 0);
				}
#endif
				if(is_rkt_pod_id_valid)
				{
					container_info.m_type = CT_RKT;
					container_info.m_id = rkt_podid + ":" + rkt_appname;
					container_info.m_name = rkt_appname;
					return true;
				}
			}
		}
	}

	// Try parsing from process root,
	// Strings used to detect rkt stage1-cores pods
	// TODO: detecting stage1-coreos rkt pods in this way is deprecated
	// we can remove it in the future
	static const string COREOS_PREFIX = "/opt/stage2/";
	static const string COREOS_APP_SUFFIX = "/rootfs";
	static const string COREOS_PODID_VAR = "container_uuid=";

	auto prefix = tinfo->m_root.find(COREOS_PREFIX);
	if(prefix == 0)
	{
		auto suffix = tinfo->m_root.find(COREOS_APP_SUFFIX, prefix);
		if(suffix != string::npos)
		{
			bool valid_id = false;
			rkt_appname = tinfo->m_root.substr(prefix + COREOS_PREFIX.size(), suffix - prefix - COREOS_PREFIX.size());
			// It is a rkt pod with stage1-coreos

			sinsp_threadinfo::visitor_func_t visitor = [&] (sinsp_threadinfo *ptinfo)
			{
				for(const auto& env_var : ptinfo->get_env())
				{
					auto container_uuid_pos = env_var.find(COREOS_PODID_VAR);
					if(container_uuid_pos == 0)
					{
						rkt_podid = env_var.substr(COREOS_PODID_VAR.size());
						container_info.m_type = CT_RKT;
						container_info.m_id = rkt_podid + ":" + rkt_appname;
						container_info.m_name = rkt_appname;
						valid_id = true;
						return false;
					}
				}
				return true;
			};

			// Try the current thread first. visitor returns true if no coreos pid
			// info was found. In this case we traverse the parents.
			if (visitor(tinfo))
			{
				tinfo->traverse_parent_state(visitor);
			}
			return valid_id;
		}
	}
	else
	{
		// String used to detect stage1-fly pods
		static const string FLY_PREFIX = "/var/lib/rkt/pods/run/";
		static const string FLY_PODID_SUFFIX = "/stage1/rootfs/opt/stage2/";
		static const string FLY_APP_SUFFIX = "/rootfs";

		auto prefix = tinfo->m_root.find(FLY_PREFIX);
		if(prefix == 0)
		{
			auto podid_suffix = tinfo->m_root.find(FLY_PODID_SUFFIX, prefix+FLY_PREFIX.size());
			if(podid_suffix != string::npos)
			{
				rkt_podid = tinfo->m_root.substr(prefix + FLY_PREFIX.size(), podid_suffix - prefix - FLY_PREFIX.size());
				auto appname_suffix = tinfo->m_root.find(FLY_APP_SUFFIX, podid_suffix+FLY_PODID_SUFFIX.size());
				if(appname_suffix != string::npos)
				{
					rkt_appname = tinfo->m_root.substr(podid_suffix + FLY_PODID_SUFFIX.size(),
									   appname_suffix-podid_suffix-FLY_PODID_SUFFIX.size());
					container_info.m_type = CT_RKT;
					container_info.m_id = rkt_podid + ":" + rkt_appname;
					container_info.m_name = rkt_appname;
					return true;
				}
			}
		}
	}
	return false;
}

bool rkt::rkt::resolve(sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	container_cache_interface *cache = &container_cache();

	auto container = std::make_shared<sinsp_container_info>();
	string rkt_podid, rkt_appname;

	if (!match(cache, tinfo, *container, rkt_podid, rkt_appname, query_os_for_missing_info))
	{
		return false;
	}

	tinfo->m_container_id = container->m_id;
	if (!query_os_for_missing_info || !cache->should_lookup(container->m_id, CT_RKT))
	{
		return true;
	}

#ifndef _WIN32
	bool have_rkt = parse_rkt(*container, rkt_podid, rkt_appname);
#else
	bool have_rkt = true;
#endif

	if (have_rkt)
	{
		cache->add_container(container, tinfo);
		cache->notify_new_container(*container);
		return true;
	}
	else
	{
		return false;
	}
}

bool rkt::rkt::parse_rkt(sinsp_container_info &container, const string &podid, const string &appname)
{
	bool ret = false;
	Json::Reader reader;
	Json::Value jroot;

	char image_manifest_path[SCAP_MAX_PATH_SIZE];
	snprintf(image_manifest_path, sizeof(image_manifest_path), "%s/var/lib/rkt/pods/run/%s/appsinfo/%s/manifest", scap_get_host_root(), podid.c_str(), appname.c_str());
	ifstream image_manifest(image_manifest_path);
	if(reader.parse(image_manifest, jroot))
	{
		container.m_image = jroot["name"].asString();
		for(const auto& label_entry : jroot["labels"])
		{
			container.m_labels.emplace(label_entry["name"].asString(), label_entry["value"].asString());
		}
		auto version_label_it = container.m_labels.find("version");
		if(version_label_it != container.m_labels.end())
		{
			container.m_image += ":" + version_label_it->second;
		}
		ret = true;
	}

	char net_info_path[SCAP_MAX_PATH_SIZE];
	snprintf(net_info_path, sizeof(net_info_path), "%s/var/lib/rkt/pods/run/%s/net-info.json", scap_get_host_root(), podid.c_str());
	ifstream net_info(net_info_path);
	if(reader.parse(net_info, jroot) && jroot.size() > 0)
	{
		const auto& first_net = jroot[0];
		if(inet_pton(AF_INET, first_net["ip"].asCString(), &container.m_container_ip) == -1)
		{
			ASSERT(false);
		}
		container.m_container_ip = ntohl(container.m_container_ip);
	}

	char pod_manifest_path[SCAP_MAX_PATH_SIZE];
	snprintf(pod_manifest_path, sizeof(pod_manifest_path), "%s/var/lib/rkt/pods/run/%s/pod", scap_get_host_root(), podid.c_str());
	ifstream pod_manifest(pod_manifest_path);
	unordered_map<string, uint32_t> image_ports;
	if(reader.parse(pod_manifest, jroot) && jroot.size() > 0)
	{
		for(const auto& japp : jroot["apps"])
		{
			if (japp["name"].asString() == appname)
			{
				for(const auto& image_port : japp["app"]["ports"])
				{
					image_ports[image_port["name"].asString()] = image_port["port"].asUInt();
				}
				break;
			}
		}
		for(const auto& jport : jroot["ports"])
		{
			auto host_port = jport["hostPort"].asUInt();
			auto container_port_it = image_ports.find(jport["name"].asString());
			if(host_port > 0 && container_port_it != image_ports.end())
			{
				sinsp_container_info::container_port_mapping port_mapping;
				port_mapping.m_host_port = host_port;
				port_mapping.m_container_port = container_port_it->second;
				container.m_port_mappings.emplace_back(move(port_mapping));
			}
		}
	}
	return ret;
}
