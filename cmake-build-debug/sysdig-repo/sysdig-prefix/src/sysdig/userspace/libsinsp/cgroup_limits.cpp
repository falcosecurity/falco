#include "cgroup_limits.h"

#include <fstream>
#include "cgroup_list_counter.h"
#include "sinsp.h"

namespace {
// to prevent 32-bit number of kilobytes from overflowing, ignore values larger than 4 TiB.
// This reports extremely large values (e.g. almost-but-not-quite 9EiB as set by k8s) as unlimited.
// Note: we use the same maximum value for cpu shares/quotas as well; the typical values are much lower
// and so should never exceed CGROUP_VAL_MAX either
constexpr const int64_t CGROUP_VAL_MAX = (1ULL << 42u) - 1;

/**
 * \brief Read a single int64_t value from cgroupfs
 * @param subsys path to the specific cgroup subsystem, e.g. /sys/fs/cgroup/cpu
 * @param cgroup cgroup path within the cgroup mountpoint (like in /proc/pid/cgroup)
 * @param filename the filename within the cgroup directory, e.g. cpu.shares
 * @param out reference to the output value
 * @return true if we successfully read the value and it's within reasonable range,
 *          reasonable being [0; CGROUP_VAL_MAX)
 */
bool read_cgroup_val(std::shared_ptr<std::string>& subsys,
		     const std::string& cgroup,
		     const std::string& filename,
		     int64_t& out)
{
	std::string path = *subsys.get() + "/" + cgroup + "/" + filename;
	std::ifstream cg_val(path);

	int64_t val = -1;
	cg_val >> val;

	if(val <= 0 || val > CGROUP_VAL_MAX)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "(cgroup-limits) value of %s (%lld) out of range, ignoring",
			path.c_str(), val);
		return false;
	}
	out = val;
	return true;
}

/**
 * Read from a cpuset file to get the number of cpus in the cpuset
 */
bool read_cgroup_list_count(const std::string& subsys,
			    const std::string& cgroup,
			    const std::string& filename,
			    int32_t& out)
{
	std::string path = subsys + "/" + cgroup + "/" + filename;
	std::ifstream cg_val(path);

	if(!cg_val)
	{
		return false;
	}

 	std::string cpuset_cpus((std::istreambuf_iterator<char>(cg_val)),
			    std::istreambuf_iterator<char>());

	if(cpuset_cpus.empty())
	{
		return false;
	}

 	libsinsp::cgroup_list_counter counter;
	out = counter(cpuset_cpus.c_str());

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"(cgroup-limits) Pulling cpu set from %s: %s = %d",
			path.c_str(),
			cpuset_cpus.c_str(),
			out);

 	return (out > 0);
}

}

namespace libsinsp {
namespace cgroup_limits {

bool get_cgroup_resource_limits(const cgroup_limits_key& key, cgroup_limits_value& value, bool name_check)
{
	bool found_all = true;
	std::shared_ptr<std::string> memcg_root = sinsp::lookup_cgroup_dir("memory");
	if(name_check && key.m_mem_cgroup.find(key.m_container_id) == std::string::npos)
	{
		g_logger.format(sinsp_logger::SEV_INFO, "(cgroup-limits) mem cgroup for container [%s]: %s/%s -- no per-container memory cgroup, ignoring",
			key.m_container_id.c_str(), memcg_root->c_str(), key.m_mem_cgroup.c_str());
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "(cgroup-limits) mem cgroup for container [%s]: %s/%s",
			key.m_container_id.c_str(), memcg_root->c_str(), key.m_mem_cgroup.c_str());
		found_all = read_cgroup_val(memcg_root, key.m_mem_cgroup, "memory.limit_in_bytes", value.m_memory_limit) && found_all;
	}

	std::shared_ptr<std::string> cpucg_root = sinsp::lookup_cgroup_dir("cpu");
	if(name_check && key.m_cpu_cgroup.find(key.m_container_id) == std::string::npos)
	{
		g_logger.format(sinsp_logger::SEV_INFO, "(cgroup-limits) cpu cgroup for container [%s]: %s/%s -- no per-container CPU cgroup, ignoring",
				key.m_container_id.c_str(), cpucg_root->c_str(), key.m_cpu_cgroup.c_str());
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "(cgroup-limits) cpu cgroup for container [%s]: %s/%s",
				key.m_container_id.c_str(), cpucg_root->c_str(), key.m_cpu_cgroup.c_str());
		found_all = read_cgroup_val(cpucg_root, key.m_cpu_cgroup, "cpu.shares", value.m_cpu_shares) && found_all;
		found_all = read_cgroup_val(cpucg_root, key.m_cpu_cgroup, "cpu.cfs_quota_us", value.m_cpu_quota) && found_all;
		found_all = read_cgroup_val(cpucg_root, key.m_cpu_cgroup, "cpu.cfs_period_us", value.m_cpu_period) && found_all;
	}

	std::shared_ptr<std::string> cpuset_root = sinsp::lookup_cgroup_dir("cpuset");
	if (name_check && key.m_cpuset_cgroup.find(key.m_container_id) == std::string::npos)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "(cgroup-limits) cpuset cgroup for container [%s]: %s/%s -- no per-container cpuset cgroup, ignoring",
				key.m_container_id.c_str(), cpuset_root->c_str(), key.m_cpuset_cgroup.c_str());
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "(cgroup-limits) cpuset cgroup for container [%s]: %s/%s",
				key.m_container_id.c_str(), cpuset_root->c_str(), key.m_cpuset_cgroup.c_str());
		found_all = read_cgroup_list_count(*cpuset_root,
						   key.m_cpuset_cgroup,
						   "cpuset.cpus",
						   value.m_cpuset_cpu_count) && found_all;
	}

	g_logger.format(sinsp_logger::SEV_DEBUG,
		"(cgroup-limits) Got cgroup limits for container [%s]: "
		"mem_limit=%ld, cpu_shares=%ld cpu_quota=%ld cpu_period=%ld cpuset_cpu_count=%d",
		key.m_container_id.c_str(),
		value.m_memory_limit, value.m_cpu_shares, value.m_cpu_quota, value.m_cpu_period, value.m_cpuset_cpu_count);

	return found_all;
}
}
}
