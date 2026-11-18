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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

namespace {

// Listens on a loopback port and answers one request for each given status, in
// order. Records the body of each request.
class http_status_server {
public:
	explicit http_status_server(const std::vector<int>& statuses): m_statuses(statuses) {
		m_fd = socket(AF_INET, SOCK_STREAM, 0);
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		socklen_t len = sizeof(addr);
		if(m_fd < 0 || bind(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
		   listen(m_fd, 1) != 0 ||
		   getsockname(m_fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
			return;
		}
		m_port = ntohs(addr.sin_port);
		m_thread = std::thread([this] { serve(); });
	}

	~http_status_server() {
		wait();
		if(m_fd >= 0) {
			close(m_fd);
		}
	}

	bool ok() const { return m_port != 0; }

	std::string url() const { return "http://127.0.0.1:" + std::to_string(m_port) + "/"; }

	// Wait until every request has been answered.
	void wait() {
		if(m_thread.joinable()) {
			m_thread.join();
		}
	}

	std::vector<std::string> bodies;

private:
	void serve() {
		for(int status : m_statuses) {
			pollfd pfd{m_fd, POLLIN, 0};
			if(poll(&pfd, 1, 10000) != 1) {
				return;
			}
			int conn = accept(m_fd, nullptr, nullptr);
			if(conn < 0) {
				return;
			}
			bodies.push_back(read_body(conn));
			const std::string response =
			        "HTTP/1.1 " + std::to_string(status) +
			        " Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
			send(conn, response.data(), response.size(), 0);
			close(conn);
		}
	}

	static std::string read_body(int conn) {
		std::string data;
		size_t headers_end = std::string::npos;
		size_t content_length = 0;
		char buf[4096];
		while(headers_end == std::string::npos || data.size() < headers_end + content_length) {
			pollfd pfd{conn, POLLIN, 0};
			if(poll(&pfd, 1, 10000) != 1) {
				break;
			}
			ssize_t n = recv(conn, buf, sizeof(buf), 0);
			if(n <= 0) {
				break;
			}
			data.append(buf, n);
			if(headers_end == std::string::npos &&
			   (headers_end = data.find("\r\n\r\n")) != std::string::npos) {
				headers_end += 4;
				std::string headers = data.substr(0, headers_end);
				std::transform(headers.begin(), headers.end(), headers.begin(), ::tolower);
				auto pos = headers.find("content-length:");
				if(pos != std::string::npos) {
					content_length = std::stoul(headers.substr(pos + 15));
				}
			}
		}
		return headers_end == std::string::npos ? "" : data.substr(headers_end);
	}

	std::vector<int> m_statuses;
	int m_fd = -1;
	uint16_t m_port = 0;
	std::thread m_thread;
};

falco::outputs::config http_config(const std::string& url) {
	falco::outputs::config oc;
	oc.name = "http";
	oc.options["url"] = url;
	oc.options["user_agent"] = "falcosecurity/falco";
	oc.options["insecure"] = "false";
	oc.options["echo"] = "false";
	oc.options["ca_cert"] = "";
	oc.options["ca_bundle"] = "";
	oc.options["ca_path"] = "/etc/ssl/certs";
	oc.options["mtls"] = "false";
	oc.options["client_cert"] = "";
	oc.options["client_key"] = "";
	oc.options["compress_uploads"] = "false";
	oc.options["keep_alive"] = "false";
	oc.options["max_consecutive_timeouts"] = "0";
	return oc;
}

}  // namespace

// The server receives the alert but answers with an error: the alert is lost,
// so the output must report it instead of failing silently.
TEST(OutputsHttp, error_status_is_reported) {
	for(int status : {400, 404, 500, 503}) {
		http_status_server server({status});
		ASSERT_TRUE(server.ok());

		falco::outputs::output_http out;
		falco::outputs::abstract_output& output = out;
		std::string err;
		ASSERT_TRUE(output.init(http_config(server.url()), false, "host", true, err)) << err;

		falco::outputs::message msg;
		msg.msg = R"({"output":"alert"})";
		try {
			output.output(&msg);
			ADD_FAILURE() << "HTTP status " << status << " was not reported";
		} catch(const falco_exception& e) {
			// the error names the status
			EXPECT_NE(std::string(e.what()).find(std::to_string(status)), std::string::npos)
			        << e.what();
		}
		server.wait();
		output.cleanup();
	}
}

// Other statuses are not errors. A redirect is not followed, but it is not
// reported either: e.g. a 303 can follow a POST that succeeded.
TEST(OutputsHttp, other_statuses_are_not_reported) {
	for(int status : {200, 202, 303}) {
		http_status_server server({status});
		ASSERT_TRUE(server.ok());

		falco::outputs::output_http out;
		falco::outputs::abstract_output& output = out;
		std::string err;
		ASSERT_TRUE(output.init(http_config(server.url()), false, "host", true, err)) << err;

		falco::outputs::message msg;
		msg.msg = R"({"output":"alert"})";
		EXPECT_NO_THROW(output.output(&msg)) << "HTTP status " << status;
		server.wait();
		output.cleanup();
	}
}

// An error status does not break the output: the next alert is still delivered.
TEST(OutputsHttp, next_alert_is_delivered_after_error_status) {
	http_status_server server({500, 200});
	ASSERT_TRUE(server.ok());

	falco::outputs::output_http out;
	falco::outputs::abstract_output& output = out;
	std::string err;
	ASSERT_TRUE(output.init(http_config(server.url()), false, "host", true, err)) << err;

	falco::outputs::message first;
	first.msg = R"({"output":"first"})";
	falco::outputs::message second;
	second.msg = R"({"output":"second"})";
	EXPECT_THROW(output.output(&first), falco_exception);
	EXPECT_NO_THROW(output.output(&second));
	server.wait();
	output.cleanup();

	// both alerts reached the server
	EXPECT_EQ(server.bodies, (std::vector<std::string>{first.msg, second.msg}));
}
