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
#include <zlib.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <thread>

namespace {

// Records a single HTTP request on a loopback port and answers 200 OK.
class one_shot_http_server {
public:
	one_shot_http_server() {
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

	~one_shot_http_server() {
		wait();
		if(m_fd >= 0) {
			close(m_fd);
		}
	}

	bool ok() const { return m_port != 0; }

	std::string url() const { return "http://127.0.0.1:" + std::to_string(m_port) + "/"; }

	void wait() {
		if(m_thread.joinable()) {
			m_thread.join();
		}
	}

	// Lowercase request headers, and the raw request body.
	std::string headers;
	std::string body;

private:
	void serve() {
		pollfd pfd{m_fd, POLLIN, 0};
		if(poll(&pfd, 1, 10000) != 1) {
			return;
		}
		int conn = accept(m_fd, nullptr, nullptr);
		if(conn < 0) {
			return;
		}
		std::string data;
		size_t headers_end = std::string::npos;
		size_t content_length = 0;
		char buf[4096];
		while(headers_end == std::string::npos || data.size() < headers_end + content_length) {
			pfd = {conn, POLLIN, 0};
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
				headers = data.substr(0, headers_end);
				std::transform(headers.begin(), headers.end(), headers.begin(), ::tolower);
				auto pos = headers.find("content-length:");
				if(pos != std::string::npos) {
					content_length = std::stoul(headers.substr(pos + 15));
				}
			}
		}
		if(headers_end != std::string::npos) {
			body = data.substr(headers_end);
		}
		const std::string response =
		        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
		send(conn, response.data(), response.size(), 0);
		close(conn);
	}

	int m_fd = -1;
	uint16_t m_port = 0;
	std::thread m_thread;
};

std::string gunzip(const std::string& in) {
	z_stream zs{};
	if(inflateInit2(&zs, 15 + 16) != Z_OK) {
		return "<inflateInit2 failed>";
	}
	std::string out(64 * 1024, '\0');
	zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
	zs.avail_in = static_cast<uInt>(in.size());
	zs.next_out = reinterpret_cast<Bytef*>(&out[0]);
	zs.avail_out = static_cast<uInt>(out.size());
	const int ret = inflate(&zs, Z_FINISH);
	out.resize(zs.total_out);
	inflateEnd(&zs);
	return ret == Z_STREAM_END ? out : "<not a gzip stream>";
}

falco::outputs::config http_config(const std::string& url, bool compress_uploads) {
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
	oc.options["compress_uploads"] = compress_uploads ? "true" : "false";
	oc.options["keep_alive"] = "false";
	oc.options["max_consecutive_timeouts"] = "0";
	return oc;
}

}  // namespace

TEST(OutputsHttp, compress_uploads_sends_gzip_payload) {
	one_shot_http_server server;
	ASSERT_TRUE(server.ok());

	falco::outputs::output_http out;
	falco::outputs::abstract_output& output = out;
	std::string err;
	ASSERT_TRUE(output.init(http_config(server.url(), true), false, "host", true, err)) << err;

	falco::outputs::message msg;
	msg.msg = R"({"output":"alert alert alert alert alert alert alert alert"})";
	output.output(&msg);
	server.wait();
	output.cleanup();

	EXPECT_NE(server.headers.find("content-encoding: gzip\r\n"), std::string::npos)
	        << server.headers;
	EXPECT_NE(server.body, msg.msg);
	EXPECT_EQ(gunzip(server.body), msg.msg);
}

TEST(OutputsHttp, uncompressed_payload_by_default) {
	one_shot_http_server server;
	ASSERT_TRUE(server.ok());

	falco::outputs::output_http out;
	falco::outputs::abstract_output& output = out;
	std::string err;
	ASSERT_TRUE(output.init(http_config(server.url(), false), false, "host", true, err)) << err;

	falco::outputs::message msg;
	msg.msg = R"({"output":"alert"})";
	output.output(&msg);
	server.wait();
	output.cleanup();

	EXPECT_EQ(server.headers.find("content-encoding:"), std::string::npos) << server.headers;
	EXPECT_EQ(server.body, msg.msg);
}
