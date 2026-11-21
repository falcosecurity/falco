// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <gtest/gtest.h>
#include <falco/outputs_http.h>

#include <curl/curl.h>
#include <httplib.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace {

// libcurl requires a one-time global init before any handle is used.
struct curl_global_initializer {
	curl_global_initializer() { curl_global_init(CURL_GLOBAL_DEFAULT); }
	~curl_global_initializer() { curl_global_cleanup(); }
};

const curl_global_initializer g_curl_global_initializer;

// Short unique directory: sun_path is limited to 108 bytes.
std::string unique_socket_directory() {
	static std::atomic<unsigned> counter{0};
	return "/tmp/falco-uds-" + std::to_string(getpid()) + "-" + std::to_string(counter++);
}

class temp_socket_directory {
public:
	temp_socket_directory(): m_directory(unique_socket_directory()) {
		std::filesystem::create_directories(m_directory);
	}

	~temp_socket_directory() {
		std::error_code ec;
		std::filesystem::remove_all(m_directory, ec);
	}

	temp_socket_directory(const temp_socket_directory &) = delete;
	temp_socket_directory &operator=(const temp_socket_directory &) = delete;

	std::string child(const std::string &name) const { return m_directory + "/" + name; }

private:
	std::string m_directory;
};

falco::outputs::config http_config(const std::string &url, const std::string &unix_socket_path) {
	falco::outputs::config oc;
	oc.name = "http";
	oc.options["url"] = url;
	oc.options["user_agent"] = "falcosecurity/falco";
	oc.options["insecure"] = "false";
	oc.options["echo"] = "false";
	oc.options["mtls"] = "false";
	oc.options["compress_uploads"] = "false";
	oc.options["keep_alive"] = "false";
	oc.options["max_consecutive_timeouts"] = "5";
	// TLS settings are not exercised here; keep the CA path portable instead of
	// assuming the Linux default location exists on every development machine.
	oc.options["ca_cert"] = "";
	oc.options["ca_bundle"] = "";
	oc.options["ca_path"] = "";
	oc.options["client_cert"] = "";
	oc.options["client_key"] = "";
	oc.options["unix_socket_path"] = unix_socket_path;
	return oc;
}

falco::outputs::message alert_message(const std::string &content) {
	falco::outputs::message msg;
	msg.ts = 0;
	msg.priority = falco_common::PRIORITY_WARNING;
	msg.msg = content;
	msg.rule = "some rule";
	msg.source = "syscall";
	return msg;
}

// Minimal HTTP server listening on a file system unix domain socket.
class unix_socket_http_server {
public:
	unix_socket_http_server(): m_path(m_directory.child("s")) {}

	~unix_socket_http_server() { stop(); }

	bool start() {
		m_server.set_address_family(AF_UNIX);
		if(!m_server.bind_to_port(m_path, 80)) {
			return false;
		}
		m_thread = std::thread([this] { m_server.listen_after_bind(); });
		return true;
	}

	void stop() {
		m_server.stop();
		if(m_thread.joinable()) {
			m_thread.join();
		}
	}

	httplib::Server &server() { return m_server; }
	const std::string &path() const { return m_path; }

private:
	temp_socket_directory m_directory;
	std::string m_path;
	httplib::Server m_server;
	std::thread m_thread;
};

struct received_request {
	std::string path;
	std::string host;
	std::string content_type;
	std::string body;
};

// Registers a handler that captures the first POST to /events.
std::future<received_request> capture_post(httplib::Server &server) {
	auto promise = std::make_shared<std::promise<received_request>>();
	server.Post("/events", [promise](const httplib::Request &req, httplib::Response &res) {
		try {
			promise->set_value(received_request{req.path,
			                                    req.get_header_value("Host"),
			                                    req.get_header_value("Content-Type"),
			                                    req.body});
		} catch(const std::future_error &) {
			// more than one alert was delivered
		}
		res.status = 200;
	});
	return promise->get_future();
}

}  // namespace

TEST(OutputsHttp, posts_alert_over_unix_socket) {
	unix_socket_http_server server;
	auto received = capture_post(server.server());
	ASSERT_TRUE(server.start());

	falco::outputs::output_http out;
	falco::outputs::abstract_output &output = out;
	std::string err;
	ASSERT_TRUE(output.init(http_config("http://localhost/events", server.path()),
	                        false,
	                        "host",
	                        true,
	                        err))
	        << err;

	auto msg = alert_message("alert body");
	output.output(&msg);
	output.cleanup();

	ASSERT_EQ(received.wait_for(std::chrono::seconds(10)), std::future_status::ready);
	auto req = received.get();
	EXPECT_EQ(req.path, "/events");
	EXPECT_EQ(req.host, "localhost");
	EXPECT_EQ(req.content_type, "application/json");
	EXPECT_EQ(req.body, "alert body");
}

TEST(OutputsHttp, follows_symlink_to_unix_socket) {
	unix_socket_http_server server;
	auto received = capture_post(server.server());
	ASSERT_TRUE(server.start());

	temp_socket_directory directory;
	const std::string link = directory.child("link");
	std::filesystem::create_symlink(server.path(), link);

	falco::outputs::output_http out;
	falco::outputs::abstract_output &output = out;
	std::string err;
	ASSERT_TRUE(output.init(http_config("http://localhost/events", link), false, "host", true, err))
	        << err;

	auto msg = alert_message("through a symlink");
	output.output(&msg);
	output.cleanup();

	ASSERT_EQ(received.wait_for(std::chrono::seconds(10)), std::future_status::ready);
	auto req = received.get();
	EXPECT_EQ(req.path, "/events");
	EXPECT_EQ(req.body, "through a symlink");
}

TEST(OutputsHttp, never_falls_back_to_tcp) {
	httplib::Server tcp;
	std::atomic<bool> tcp_request_received{false};
	tcp.Post("/events", [&tcp_request_received](const httplib::Request &, httplib::Response &res) {
		tcp_request_received = true;
		res.status = 200;
	});
	const int port = tcp.bind_to_any_port("127.0.0.1");
	ASSERT_GT(port, 0);
	std::thread tcp_thread([&tcp] { tcp.listen_after_bind(); });

	temp_socket_directory directory;
	const std::string missing_socket = directory.child("missing");

	falco::outputs::output_http out;
	falco::outputs::abstract_output &output = out;
	std::string err;
	// A missing socket is not a configuration error, but it must not turn into TCP.
	ASSERT_TRUE(output.init(
	        http_config("http://127.0.0.1:" + std::to_string(port) + "/events", missing_socket),
	        false,
	        "host",
	        true,
	        err))
	        << err;

	auto msg = alert_message("must not reach tcp");
	output.output(&msg);
	output.cleanup();

	tcp.stop();
	tcp_thread.join();
	EXPECT_FALSE(tcp_request_received.load());
}

TEST(OutputsHttp, rejects_path_that_is_not_a_socket) {
	temp_socket_directory directory;
	const std::string file = directory.child("file");
	{
		std::ofstream out(file);
		out << "not a socket\n";
	}

	falco::outputs::output_http out;
	falco::outputs::abstract_output &output = out;
	std::string err;
	EXPECT_FALSE(
	        output.init(http_config("http://localhost/events", file), false, "host", true, err));
	EXPECT_NE(err.find("not a socket"), std::string::npos) << err;
}

TEST(OutputsHttp, rejects_directory_as_socket_path) {
	temp_socket_directory directory;
	const std::string dir = directory.child("dir");
	std::filesystem::create_directories(dir);

	falco::outputs::output_http out;
	falco::outputs::abstract_output &output = out;
	std::string err;
	EXPECT_FALSE(
	        output.init(http_config("http://localhost/events", dir), false, "host", true, err));
	EXPECT_NE(err.find("not a socket"), std::string::npos) << err;
}
