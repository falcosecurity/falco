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

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <sinsp.h>
#include <nlohmann/json.hpp>

namespace falco
{
    /**
     * @brief Container for the version of Falco components
     */
    struct versions_info
    {
        /**
         * @brief Construct a versions info by using an inspector to obtain
         * versions about the drivers and the loaded plugins.
         */
        versions_info(const std::shared_ptr<sinsp>& inspector);
        versions_info(versions_info&&) = default;
        versions_info& operator = (versions_info&&) = default;
        versions_info(const versions_info& s) = default;
        versions_info& operator = (const versions_info& s) = default;

        /**
         * @brief Encode the versions info as a JSON object
         */
        nlohmann::json as_json() const;

        std::string falco_version;
        std::string engine_version;
        std::string libs_version;
        std::string plugin_api_version;
        std::string driver_api_version;
        std::string driver_schema_version;
        std::string default_driver_version;
        std::unordered_map<std::string, std::string> plugin_versions;
    };
};
