// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include "versions_info.h"

#include <libsinsp/plugin_manager.h>

// todo: move string conversion to scap
static std::string get_driver_api_version(const std::shared_ptr<sinsp>& s)
{
    auto driver_api_version = s->get_scap_api_version();
    unsigned long driver_api_major = PPM_API_VERSION_MAJOR(driver_api_version);
    unsigned long driver_api_minor = PPM_API_VERSION_MINOR(driver_api_version);
    unsigned long driver_api_patch = PPM_API_VERSION_PATCH(driver_api_version);

    char driver_api_version_string[32];
    snprintf(driver_api_version_string, sizeof(driver_api_version_string), "%lu.%lu.%lu", driver_api_major, driver_api_minor, driver_api_patch);
    return std::string(driver_api_version_string);
}

// todo: move string conversion to scap
static inline std::string get_driver_schema_version(const std::shared_ptr<sinsp>& s)
{
    auto driver_schema_version = s->get_scap_schema_version();
    unsigned long driver_schema_major = PPM_API_VERSION_MAJOR(driver_schema_version);
    unsigned long driver_schema_minor = PPM_API_VERSION_MINOR(driver_schema_version);
    unsigned long driver_schema_patch = PPM_API_VERSION_PATCH(driver_schema_version);

    char driver_schema_version_string[32];
    snprintf(driver_schema_version_string, sizeof(driver_schema_version_string), "%lu.%lu.%lu", driver_schema_major, driver_schema_minor, driver_schema_patch);
    return std::string(driver_schema_version_string);
}

falco::versions_info::versions_info(const std::shared_ptr<sinsp>& inspector)
    : plugin_api_version(inspector->get_plugin_api_version())
    , driver_api_version(get_driver_api_version(inspector))
    , driver_schema_version(get_driver_schema_version(inspector))
{
    for (const auto &p : inspector->get_plugin_manager()->plugins())
    {
        plugin_versions[p->name()] = p->plugin_version().as_string();
    }
}

nlohmann::json falco::versions_info::as_json() const
{
    nlohmann::json version_info;
    version_info["falco_version"] = falco_version;
    version_info["libs_version"] = libs_version;
    version_info["plugin_api_version"] = plugin_api_version;
    version_info["driver_api_version"] = driver_api_version;
    version_info["driver_schema_version"] = driver_schema_version;
    version_info["default_driver_version"] = default_driver_version;
    // note: the 'engine_version' key below must be removed in the next major bump (0.x.y -> 1.0.0)
    // the two keys are kept for existing tooling that relies on the old key
    // (falcoctl will match old rules artifacts configs by using this key, and the new ones using 
    // the engine_version_semver key)
    version_info["engine_version"] = std::to_string(FALCO_ENGINE_VERSION_MINOR);
    version_info["engine_version_semver"] = engine_version;
    for (const auto& pv : plugin_versions)
    {
        version_info["plugin_versions"][pv.first] = pv.second;
    }
    return version_info;
}
