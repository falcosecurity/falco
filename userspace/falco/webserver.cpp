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

#include "webserver.h"
#include "falco_utils.h"
#include "versions_info.h"
#include <atomic>

falco_webserver::~falco_webserver()
{
    stop();
}

void falco_webserver::start(
        const std::shared_ptr<sinsp>& inspector,
        uint32_t threadiness,
        uint32_t listen_port,
        std::string& listen_address,
        std::string& healthz_endpoint,
        std::string &ssl_certificate,
        bool ssl_enabled)
{
    if (m_running)
    {
        throw falco_exception(
            "attempted restarting webserver without stopping it first");
    }

    // allocate and configure server
    if (ssl_enabled)
    {
        m_server = std::make_unique<httplib::SSLServer>(
            ssl_certificate.c_str(),
            ssl_certificate.c_str());
    }
    else
    {
        m_server = std::make_unique<httplib::Server>();
    }

    // configure server
    m_server->new_task_queue = [&threadiness] { return new httplib::ThreadPool(threadiness); };

    // setup healthz endpoint
    m_server->Get(healthz_endpoint,
        [](const httplib::Request &, httplib::Response &res) {
            res.set_content("{\"status\": \"ok\"}", "application/json");
        });
    
    // setup versions endpoint
    const auto versions_json_str = falco::versions_info(inspector).as_json().dump();
    m_server->Get("/versions",
        [versions_json_str](const httplib::Request &, httplib::Response &res) {
            res.set_content(versions_json_str, "application/json");
        });

    // run server in a separate thread
    if (!m_server->is_valid())
    {
        m_server = nullptr;
        throw falco_exception("invalid webserver configuration");
    }

    std::atomic<bool> failed;
    failed.store(false, std::memory_order_release);
    m_server_thread = std::thread([this, listen_address, listen_port, &failed]
    {
        try
        {
            this->m_server->listen(listen_address, listen_port);
        }
        catch(std::exception &e)
        {
            falco_logger::log(
                falco_logger::level::ERR,
                "falco_webserver: " + std::string(e.what()) + "\n");
        }
        failed.store(true, std::memory_order_release);
    });

    // wait for the server to actually start up
    // note: is_running() is atomic
    while (!m_server->is_running() && !failed.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }
    m_running = true;
    if (failed.load(std::memory_order_acquire))
    {
        stop();
        throw falco_exception("an error occurred while starting webserver");
    }
}

void falco_webserver::stop()
{
    if (m_running)
    {
        if (m_server != nullptr)
        {
            m_server->stop();
        }
        if(m_server_thread.joinable())
        {
            m_server_thread.join();
        }
        if (m_server != nullptr)
        {
            m_server = nullptr;
        }
        m_running = false;
    }
}
