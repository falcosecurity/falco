#pragma once

#include <string>
#include <utility>
#include "async_key_value_source.h"

namespace {
bool less_than(const std::string& lhs, const std::string& rhs, bool if_equal=false)
{
	int cmp = lhs.compare(rhs);
	if(cmp < 0)
	{
		return true;
	}
	else if(cmp > 0)
	{
		return false;
	}
	else
	{
		return if_equal;
	}
}
}

namespace libsinsp {
namespace cgroup_limits {

/**
 * \brief The key for cgroup value lookup
 *
 * It's effectively a (container_id, cpu_cgroup, mem_cgroup) tuple
 * that can be used as a hash key.
 */
struct cgroup_limits_key {
	cgroup_limits_key() {}

	cgroup_limits_key(std::string container_id,
			  std::string cpu_cgroup_dir,
			  std::string mem_cgroup_dir,
			  std::string cpuset_cgroup_dir) :
		m_container_id(std::move(container_id)),
		m_cpu_cgroup(std::move(cpu_cgroup_dir)),
		m_mem_cgroup(std::move(mem_cgroup_dir)),
		m_cpuset_cgroup(std::move(cpuset_cgroup_dir)) { }

	bool operator<(const cgroup_limits_key& rhs) const
	{
		return less_than(m_container_id, rhs.m_container_id,
				 less_than(m_cpu_cgroup, rhs.m_cpu_cgroup,
					   less_than(m_mem_cgroup, rhs.m_mem_cgroup,
						less_than(m_cpuset_cgroup, rhs.m_cpuset_cgroup))));
	}

	bool operator==(const cgroup_limits_key& rhs) const
	{
		return m_container_id == rhs.m_container_id &&
		       m_cpu_cgroup == rhs.m_cpu_cgroup &&
		       m_mem_cgroup == rhs.m_mem_cgroup &&
		       m_cpuset_cgroup == rhs.m_cpuset_cgroup;
	}

	explicit operator const std::string&() const
	{
		return m_container_id;
	}

	std::string m_container_id;
	std::string m_cpu_cgroup;
	std::string m_mem_cgroup;
	std::string m_cpuset_cgroup;
};

/**
 * \brief The result of an asynchronous cgroup lookup
 *
 * This contains all the cgroup values we read during the asynchronous lookup
 */
struct cgroup_limits_value {
	cgroup_limits_value() :
		m_cpu_shares(0),
		m_cpu_quota(0),
		m_cpu_period(0),
		m_memory_limit(0),
		m_cpuset_cpu_count(0) {}

	int64_t m_cpu_shares;
	int64_t m_cpu_quota;
	int64_t m_cpu_period;
	int64_t m_memory_limit;
	int32_t m_cpuset_cpu_count;
};

/**
 * \brief Read resource limits from cgroups
 * @param key the container to read limits for
 * @param value output value. when the return value is false, specific fields
 *         may or may not have been modified
 * @param name_check if true and the container doesn't use its own cgroups
 *         for mem/cpu, we log a message and we ignore the values.
 *         "Use its own cgroups" means the container id is present in the cgroup
 *         path, which may not be true for all container engines.
 * @return true when all values have been successfully read, false otherwise
 *
 * Note: reading a zero/negative/very large value is considered a failure,
 * because it might mean that resource limits haven't yet been set. Essentially,
 * `false` means "there's real chance the limits could conceivably change
 * in the future", while `true` means we really don't expect them to change
 * any more.
 */
bool get_cgroup_resource_limits(const cgroup_limits_key& key, cgroup_limits_value& value, bool name_check = true);

}
}

namespace std {
/**
 * \brief Specialization of std::hash for cgroup_limits_key
 *
 * It allows `cgroup_limits_key` instances to be used as `unordered_map` keys
 */
template<> struct hash<libsinsp::cgroup_limits::cgroup_limits_key> {
	std::size_t operator()(const libsinsp::cgroup_limits::cgroup_limits_key& h) const {
		size_t h1 = ::std::hash<std::string>{}(h.m_container_id);
		size_t h2 = ::std::hash<std::string>{}(h.m_cpu_cgroup);
		size_t h3 = ::std::hash<std::string>{}(h.m_mem_cgroup);
		size_t h4 = ::std::hash<std::string>{}(h.m_cpuset_cgroup);
		return h1 ^ (h2 << 1u) ^ (h3 << 2u) ^ (h4 << 3u);
	}
};
}