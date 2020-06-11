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

#include "cri.h"

#include <chrono>
#include "grpc_channel_registry.h"

#include "sinsp.h"
#include "sinsp_int.h"

namespace {
bool pod_uses_host_netns(const runtime::v1alpha2::PodSandboxStatusResponse& resp)
{
	const auto netns = resp.status().linux().namespaces().options().network();
	return netns == runtime::v1alpha2::NODE;
}
}

namespace libsinsp {
namespace cri {
std::string s_cri_unix_socket_path = "/run/containerd/containerd.sock";
int64_t s_cri_timeout = 1000;
int64_t s_cri_size_timeout = 10000;
sinsp_container_type s_cri_runtime_type = CT_CRI;
bool s_cri_extra_queries = true;

cri_interface::cri_interface(const std::string& cri_path)
{
	std::shared_ptr<grpc::Channel> channel = libsinsp::grpc_channel_registry::get_channel("unix://" + cri_path);

	m_cri = runtime::v1alpha2::RuntimeService::NewStub(channel);

	runtime::v1alpha2::VersionRequest vreq;
	runtime::v1alpha2::VersionResponse vresp;

	vreq.set_version("v1alpha2");
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = m_cri->Version(&context, vreq, &vresp);

	if (!status.ok())
	{
		g_logger.format(sinsp_logger::SEV_NOTICE, "cri: CRI runtime returned an error after version check at %s: %s",
				s_cri_unix_socket_path.c_str(), status.error_message().c_str());
		m_cri.reset(nullptr);
		s_cri_unix_socket_path = "";
		return;
	}

	g_logger.format(sinsp_logger::SEV_INFO, "cri: CRI runtime: %s %s", vresp.runtime_name().c_str(), vresp.runtime_version().c_str());

	m_cri_image = runtime::v1alpha2::ImageService::NewStub(channel);

	const std::string& runtime_name = vresp.runtime_name();
	if(runtime_name == "containerd")
	{
		m_cri_runtime_type = CT_CONTAINERD;
	} else if(runtime_name == "cri-o")
	{
		m_cri_runtime_type = CT_CRIO;
	} else
	{
		m_cri_runtime_type = CT_CRI;
	}

	s_cri_runtime_type = m_cri_runtime_type;
}

sinsp_container_type cri_interface::get_cri_runtime_type() const
{
	return m_cri_runtime_type;
}

grpc::Status cri_interface::get_container_status(const std::string& container_id, runtime::v1alpha2::ContainerStatusResponse& resp)
{
	runtime::v1alpha2::ContainerStatusRequest req;
	req.set_container_id(container_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	return m_cri->ContainerStatus(&context, req, &resp);
}

grpc::Status cri_interface::get_container_stats(const std::string& container_id, runtime::v1alpha2::ContainerStatsResponse& resp)
{
	runtime::v1alpha2::ContainerStatsRequest req;
	req.set_container_id(container_id);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_size_timeout);
	context.set_deadline(deadline);
	return m_cri->ContainerStats(&context, req, &resp);
}

bool cri_interface::parse_cri_image(const runtime::v1alpha2::ContainerStatus &status, sinsp_container_info &container)
{
	// image_ref may be one of two forms:
	// host/image@sha256:digest
	// sha256:digest

	bool have_digest = false;
	const auto &image_ref = status.image_ref();
	auto digest_start = image_ref.find("sha256:");
	switch (digest_start)
	{
	case 0: // sha256:digest
		have_digest = true;
		break;
	case string::npos:
		break;
	default: // host/image@sha256:digest
		have_digest = image_ref[digest_start - 1] == '@';
	}

	string hostname, port, digest;
	sinsp_utils::split_container_image(status.image().image(),
					   hostname,
					   port,
					   container.m_imagerepo,
					   container.m_imagetag,
					   digest,
					   false);
	container.m_image = status.image().image();


	if(have_digest)
	{
		container.m_imagedigest = image_ref.substr(digest_start);
	}
	else
	{
		container.m_imagedigest = digest;
	}
	return true;
}

bool cri_interface::parse_cri_mounts(const runtime::v1alpha2::ContainerStatus &status, sinsp_container_info &container)
{
	for(const auto &mount : status.mounts())
	{
		const char *propagation;
		switch(mount.propagation())
		{
		case runtime::v1alpha2::MountPropagation::PROPAGATION_PRIVATE:
			propagation = "private";
			break;
		case runtime::v1alpha2::MountPropagation::PROPAGATION_HOST_TO_CONTAINER:
			propagation = "rslave";
			break;
		case runtime::v1alpha2::MountPropagation::PROPAGATION_BIDIRECTIONAL:
			propagation = "rshared";
			break;
		default:
			propagation = "unknown";
			break;
		}
		container.m_mounts.emplace_back(
			mount.host_path(),
			mount.container_path(),
			"",
			!mount.readonly(),
			propagation);
	}
	return true;

}

bool walk_down_json(const Json::Value &root, const Json::Value **out, const std::string &key)
{
	if(root.isMember(key))
	{
		*out = &root[key];
		return true;
	}
	return false;
}

template<typename... Args>
bool walk_down_json(const Json::Value &root, const Json::Value **out, const std::string &key, Args... args)
{
	if(root.isMember(key))
	{
		return walk_down_json(root[key], out, args...);
	}
	return false;
}

bool set_numeric_32(const Json::Value& dict, const std::string& key, int32_t& val)
{
	if (!dict.isMember(key))
	{
		return false;
	}
	const auto& json_val = dict[key];
	if (!json_val.isNumeric())
	{
		return false;
	}
	val = json_val.asInt();
	return true;
}

bool set_numeric_64(const Json::Value &dict, const std::string &key, int64_t &val)
{
	if(!dict.isMember(key))
	{
		return false;
	}
	const auto &json_val = dict[key];
	if(!json_val.isNumeric())
	{
		return false;
	}
	val = json_val.asInt64();
	return true;
}

bool cri_interface::parse_cri_env(const Json::Value &info, sinsp_container_info &container)
{
	const Json::Value *envs;
	if(!walk_down_json(info, &envs, "config", "envs") || !envs->isArray())
	{
		return false;
	}

	for(const auto &env_var : *envs)
	{
		const auto &key = env_var["key"];
		const auto &value = env_var["value"];

		if(key.isString() && value.isString())
		{
			auto var = key.asString();
			var += '=';
			var += value.asString();
			container.m_env.emplace_back(var);
		}
	}

	return true;
}

bool cri_interface::parse_cri_json_image(const Json::Value &info, sinsp_container_info &container)
{
	const Json::Value *image;
	if(!walk_down_json(info, &image, "config", "image", "image") || !image->isString())
	{
		return false;
	}

	auto image_str = image->asString();
	auto pos = image_str.find(':');
	if(pos == string::npos)
	{
		container.m_imageid = move(image_str);
	} else
	{
		container.m_imageid = image_str.substr(pos + 1);
	}

	return true;
}

bool cri_interface::parse_cri_runtime_spec(const Json::Value &info, sinsp_container_info &container)
{
	const Json::Value *linux = nullptr;
	if(!walk_down_json(info, &linux, "runtimeSpec", "linux") || !linux->isObject())
	{
		return false;
	}

	const Json::Value *memory = nullptr;
	if(walk_down_json(*linux, &memory, "resources", "memory"))
	{
		set_numeric_64(*memory, "limit", container.m_memory_limit);
		container.m_swap_limit = container.m_memory_limit;
	}

	const Json::Value *cpu = nullptr;
	if(walk_down_json(*linux, &cpu, "resources", "cpu") && cpu->isObject())
	{
		set_numeric_64(*cpu, "shares", container.m_cpu_shares);
		set_numeric_64(*cpu, "quota", container.m_cpu_quota);
		set_numeric_64(*cpu, "period", container.m_cpu_period);
		set_numeric_32(*cpu, "cpuset_cpu_count", container.m_cpuset_cpu_count);
	}

	const Json::Value *privileged;
	if(walk_down_json(*linux, &privileged, "security_context", "privileged") && privileged->isBool())
	{
		container.m_privileged = privileged->asBool();
	}

	return true;
}

bool cri_interface::is_pod_sandbox(const std::string &container_id)
{
	runtime::v1alpha2::PodSandboxStatusRequest req;
	runtime::v1alpha2::PodSandboxStatusResponse resp;
	req.set_pod_sandbox_id(container_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = m_cri->PodSandboxStatus(&context, req, &resp);

	return status.ok();
}

uint32_t cri_interface::get_pod_sandbox_ip(const std::string &pod_sandbox_id)
{
	runtime::v1alpha2::PodSandboxStatusRequest req;
	runtime::v1alpha2::PodSandboxStatusResponse resp;
	req.set_pod_sandbox_id(pod_sandbox_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = m_cri->PodSandboxStatus(&context, req, &resp);

	if(!status.ok())
	{
		return 0;
	}

	if(pod_uses_host_netns(resp))
	{
		return 0;
	}

	const auto &pod_ip = resp.status().network().ip();
	if(pod_ip.empty())
	{
		return 0;
	}

	uint32_t ip;
	if(inet_pton(AF_INET, pod_ip.c_str(), &ip) == -1)
	{
		ASSERT(false);
		return 0;
	} else
	{
		return ip;
	}
}

uint32_t cri_interface::get_container_ip(const std::string &container_id)
{
	runtime::v1alpha2::ListContainersRequest req;
	runtime::v1alpha2::ListContainersResponse resp;
	auto filter = req.mutable_filter();
	filter->set_id(container_id);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	grpc::Status lstatus = m_cri->ListContainers(&context, req, &resp);

	switch(resp.containers_size())
	{
		case 0:
			g_logger.format(sinsp_logger::SEV_WARNING, "Container id %s not in list from CRI", container_id.c_str());
			ASSERT(false);
			break;
		case 1: {
			const auto& cri_container = resp.containers(0);
			return ntohl(get_pod_sandbox_ip(cri_container.pod_sandbox_id()));
		}
		default:
			g_logger.format(sinsp_logger::SEV_WARNING, "Container id %s matches more than once in list from CRI", container_id.c_str());
			ASSERT(false);
			break;
	}
	return 0;
}

std::string cri_interface::get_container_image_id(const std::string &image_ref)
{
	runtime::v1alpha2::ListImagesRequest req;
	runtime::v1alpha2::ListImagesResponse resp;
	auto filter = req.mutable_filter();
	auto spec = filter->mutable_image();
	spec->set_image(image_ref);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = m_cri_image->ListImages(&context, req, &resp);

	switch(resp.images_size())
	{
		case 0:
			g_logger.format(sinsp_logger::SEV_WARNING, "Image ref %s not in list from CRI", image_ref.c_str());
			ASSERT(false);
			break;
		case 1: {
			const auto& image = resp.images(0);
			return image.id();
		}
		default:
			g_logger.format(sinsp_logger::SEV_WARNING, "Image ref %s matches more than once in list from CRI", image_ref.c_str());
			ASSERT(false);
			break;
	}

	return "";
}
}
}
