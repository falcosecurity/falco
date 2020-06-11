/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

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

//
// socket_handler.h
//

#pragma once

#ifdef HAS_CAPTURE

#include "http_parser.h"
#include "uri.h"
#include "json/json.h"
#define BUFFERSIZE 512 // b64 needs this macro
#include "b64/encode.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_auth.h"
#include "http_reason.h"
#include "json_query.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <iostream>
#include <string>
#include <map>
#include <memory>
#include <cstring>
#include <climits>

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#endif

struct gaicb_free
{
	void operator() (struct gaicb **reqs) const
		{
			if(reqs[0]->ar_result)
			{
				freeaddrinfo(reqs[0]->ar_result);
			}
			if(reqs[0]->ar_name)
			{
				free((void*)reqs[0]->ar_name);
			}
			free(reqs[0]);
			free(reqs);
		}
};

template <typename T>
class socket_data_handler
{
public:
	typedef std::shared_ptr<socket_data_handler> ptr_t;
	typedef std::shared_ptr<Json::Value>         json_ptr_t;
	typedef sinsp_ssl::ptr_t                     ssl_ptr_t;
	typedef sinsp_bearer_token::ptr_t            bt_ptr_t;
	typedef void (T::*json_callback_func_t)(json_ptr_t, const std::string&);

	static const std::string HTTP_VERSION_10;
	static const std::string HTTP_VERSION_11;
	static const int CONNECTION_CLOSED = ~0;

	socket_data_handler(T& obj,
		const std::string& id,
		const std::string& url,
		const std::string& path = "",
		const std::string& http_version = HTTP_VERSION_11,
		int timeout_ms = 1000,
		ssl_ptr_t ssl = nullptr,
		bt_ptr_t bt = nullptr,
		bool keep_alive = true,
		bool blocking = false,
		unsigned data_limit = 524288u,
		bool fetching_state = true): m_obj(obj),
			m_id(id),
			m_url(url),
			m_keep_alive(keep_alive ? std::string("Connection: keep-alive\r\n") : std::string()),
			m_path(path.empty() ? m_url.get_path() : path),
			m_blocking(blocking),
			m_ssl(ssl),
			m_bt(bt),
			m_timeout_ms(timeout_ms),
			m_request(make_request(url, http_version)),
			m_http_version(http_version),
			m_data_limit(data_limit),
			m_fetching_state(fetching_state)

	{
		g_logger.log(std::string("Creating Socket handler object for (" + id + ") "
					 "[" + uri(url).to_string(false) + ']'), sinsp_logger::SEV_DEBUG);
		m_buf.resize(1024);
		init_http_parser();
	}

	virtual ~socket_data_handler()
	{
		cleanup();
	}

	virtual int get_socket(long timeout_ms = -1)
	{
		if(timeout_ms != -1)
		{
			m_timeout_ms = timeout_ms;
		}

		if(m_socket < 0 || !m_connected)
		{
			connect_socket();
		}

		return m_socket;
	}

	virtual bool is_connected() const
	{
		return m_connected;
	}

	bool is_connecting()
	{
		if(m_address.empty())
		{
			try_resolve();
		}
		if(!m_connected && m_sa && m_sa_len)
		{
			try_connect();
		}
		return m_connecting;
	}

	void close_on_chunked_end(bool close = true)
	{
		m_close_on_chunked_end = close;
	}

	const uri& get_url() const
	{
		return m_url;
	}

	void set_path(const std::string& path)
	{
		m_path = path;
		m_request = make_request(m_url, m_http_version);
	}

	std::string make_request(uri url, const std::string& http_version)
	{
		std::ostringstream request;
		std::string host_and_port = url.get_host();
		if(!host_and_port.empty())
		{
			int port = url.get_port();
			if(port)
			{
				host_and_port.append(1, ':').append(std::to_string(port));
			}
		}
		request << "GET " << m_path;
		std::string query = url.get_query();
		if(!query.empty())
		{
			request << '?' << query;
		}
		request << " HTTP/" << http_version << "\r\n" << m_keep_alive << "User-Agent: sysdig\r\n";
		if(!host_and_port.empty())
		{
			request << "Host: " << host_and_port << "\r\n";
		}
		request << "Accept: */*\r\n";
		std::string creds = url.get_credentials();
		if(!creds.empty())
		{
			uri::decode(creds);
			std::istringstream is(creds);
			std::ostringstream os;
			base64::encoder().encode(is, os);
			std::string bauth = os.str();
			request << "Authorization: Basic " << trim(bauth) << "\r\n";
		}
		if(m_bt && !m_bt->get_token().empty())
		{
			request << "Authorization: Bearer " << m_bt->get_token() << "\r\n";
		}
		request << "\r\n";

		return request.str();
	}

	void set_id(const std::string& id)
	{
		m_id = id;
	}

	const std::string& get_id() const
	{
		return m_id;
	}

	void set_json_callback(json_callback_func_t f)
	{
		m_json_callback = f;
	}

	SSL* ssl_connection()
	{
		return m_ssl_connection;
	}

	bool wants_send() const
	{
		return m_wants_send;
	}

	void send_request()
	{
		m_wants_send = false; // no matter what happens, this is a one-shot
		if(m_request.empty())
		{
			throw sinsp_exception("Socket handler (" + m_id + ") send: request (empty).");
		}

		if(m_socket <= 0)
		{
			throw sinsp_exception("Socket handler (" + m_id + ") send: invalid socket.");
		}

		int iolen = 0;
		if(m_request.size())
		{
			g_logger.log("Socket handler (" + m_id + ") socket=" + std::to_string(m_socket) +
						 ", m_ssl_connection=" + std::to_string((int64_t)m_ssl_connection), sinsp_logger::SEV_TRACE);
			std::string req = m_request;
			time_t then; time(&then);
			while(req.size())
			{
				if(m_url.is_secure())
				{
					if(!m_ssl_connection)
					{
						throw sinsp_exception("Socket handler (" + m_id + ") send: SSL connection is null.");
					}
					iolen = SSL_write(m_ssl_connection, m_request.c_str(), m_request.size());
				}
				else
				{
					iolen = send(m_socket, m_request.c_str(), m_request.size(), 0);
				}
				if(iolen == static_cast<int>(req.size())) { break; }
				else if(iolen == 0 || errno == ENOTCONN || errno == EPIPE)
				{
					goto connection_closed;
				}
				else if(iolen < 0)
				{
					if(errno == ENOTCONN || errno == EPIPE)
					{
						goto connection_closed;
					}
					else if(errno != EAGAIN && errno != EWOULDBLOCK)
					{
						goto connection_error;
					}
					if(m_url.is_secure())
					{
						int err = SSL_get_error(m_ssl_connection, iolen);
						if(err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ)
						{
							goto connection_error;
						}
					}
				}
				else { req.erase(0, iolen); }
				time_t now; time(&now);
				if(difftime(now, then) > m_timeout_ms * 1000)
				{
					throw sinsp_exception("Socket handler (" + m_id + "): send timeout.");
				}
			}
		}
		else
		{
			throw sinsp_exception("Socket handler (" + m_id + ") request is empty.");
		}
		g_logger.log(m_request, sinsp_logger::SEV_TRACE);
		return;

		connection_error:
		{
			std::string err = strerror(errno);
			std::ostringstream os;
			os << "Socket handler (" << m_id << ") send_request(), connection [" << m_url.to_string(false) << "] error: " << err;
			if(m_url.is_secure())
			{
				std::string ssl_err = ssl_errors();
				if(!ssl_err.empty())
				{
					os << std::endl << "SSL error: " << ssl_err;
				}
			}
			throw sinsp_exception(os.str());
		}

		connection_closed:
		{
			std::ostringstream os;
			os << "Socket handler (" << m_id << ") send_request(), connection [" << m_url.to_string(false) << "] closed.";
			if(m_url.is_secure())
			{
				std::string ssl_err = ssl_errors();
				if(!ssl_err.empty())
				{
					os << std::endl << "SSL error: " << ssl_err;
				}
			}
			m_connecting = false;
			m_connected = false;
			throw sinsp_exception(os.str());
		}
	}

	void set_socket_option(int opt)
	{
		int flags = fcntl(m_socket, F_GETFL, 0);
		if(flags != -1)
		{
			fcntl(m_socket, F_SETFL, flags | opt);
		}
		else
		{
			throw sinsp_exception("Socket handler (" + m_id +
								  ") error while setting socket option (" +
								  std::to_string(opt) + "): " + strerror(errno));
		}
	}

	int get_all_data()
	{
		g_logger.log("Socket handler (" + m_id + ") Retrieving all data in blocking mode ...",
					 sinsp_logger::SEV_TRACE);
		ssize_t rec = 0;
		std::vector<char> buf(1024, 0);
		int counter = 0;
		int processed = 0;
		init_http_parser();
		do
		{
			int count = 0;
			int ioret = ioctl(m_socket, FIONREAD, &count);
			if(ioret >= 0 && count > 0)
			{
				buf.resize(count);
				if(m_url.is_secure())
				{
					rec = SSL_read(m_ssl_connection, &buf[0], buf.size());
				}
				else
				{
					rec = recv(m_socket, &buf[0], buf.size(), 0);
				}
				if(rec > 0)
				{
					process(&buf[0], rec, false);
					processed += rec;
				}
				else if(rec == 0)
				{
					throw sinsp_exception("Socket handler (" + m_id + "): Connection closed.");
				}
				else if(rec < 0)
				{
					throw sinsp_exception("Socket handler (" + m_id + "): " + strerror(errno));
				}
				//g_logger.log("Socket handler (" + m_id + ") received=" + std::to_string(rec) +
				//			 "\n\n" + data + "\n\n", sinsp_logger::SEV_TRACE);
			}

                        // To prevent reads from entirely stalling (like in gigantic k8s
                        // environments), give up after reading 30mb.
			++counter;
			if(processed > 30 * 1024 * 1024)
			{
				throw sinsp_exception("Socket handler (" + m_id + "): "
						      "read more than 30MB of data from " + m_url.to_string(false) + m_path +
						      " (" + std::to_string(processed) + " bytes, " + std::to_string(counter) + " reads). Giving up");
			}
			else { usleep(10000); }
		} while(!m_msg_completed);
		init_http_parser();
		return processed;
	}

	void data_handling_error(const std::string& data, size_t nparsed)
	{
		std::ostringstream os;
		os << "Socket handler (" << m_id + ") an error occurred during http parsing. "
			"processed=" << nparsed << ", expected=" << data.size() << ", status_code=" <<
			std::to_string(m_http_parser->status_code) << ", http_errno=" <<
			std::to_string(m_http_parser->http_errno) << "data:" << std::endl << data;
		throw sinsp_exception(os.str());
	}

	void parse_http(char* data, size_t len)
	{
		size_t nparsed = http_parser_execute(m_http_parser, &m_http_parser_settings, data, len);
		if(nparsed != len) { data_handling_error(std::string(data, len), nparsed); }
	}

	void process_json()
	{
		if(m_json_filters.empty()) { add_json_filter("."); }
		bool handled = false;
		for(auto js = m_json.begin(); js != m_json.end();)
		{
			handled = false;
			for(auto it = m_json_filters.cbegin(); it != m_json_filters.cend(); ++it)
			{
				json_ptr_t pjson = try_parse(m_jq, *js, *it, m_id, m_url.to_string(false));
				if(pjson)
				{
					(m_obj.*m_json_callback)(pjson, m_id);
					handled = true;
					break;
				}
			}
			if(!handled)
			{
				g_logger.log("Socket handler: (" + m_id + ") JSON not handled, "
							 "discarding:\n" + *js, sinsp_logger::SEV_ERROR);
			}
			js = m_json.erase(js);
		}
	}

	int process(char* data, size_t len, bool reinit = true)
	{
		if(len)
		{
			parse_http(data, len);
			unsigned parser_errno = HTTP_PARSER_ERRNO(m_http_parser);
			if(parser_errno != HPE_OK)
			{
				if(parser_errno <= HPE_UNKNOWN)
				{
					g_logger.log("Socket handler (" + m_id + ") http parser error " + std::to_string(parser_errno) + " ([" +
								http_errno_name((http_errno) parser_errno) + "]: " +
								http_errno_description((http_errno) parser_errno) + ')',
								sinsp_logger::SEV_ERROR);
				}
				else
				{
					g_logger.log("Socket handler (" + m_id + ") http parser error " + std::to_string(parser_errno) + ')',
								 sinsp_logger::SEV_ERROR);
				}
				return CONNECTION_CLOSED;
			}
			if(m_json.size()) { process_json(); }
			if(m_http_response >= 400)
			{
				g_logger.log("Socket handler (" + m_id + ") response " + std::to_string(m_http_response) +
							" (" + get_http_reason(m_http_response) + ") received, disconnecting ... ",
							sinsp_logger::SEV_ERROR);
				return CONNECTION_CLOSED;
			}
			if(m_msg_completed)
			{
				if(m_data_buf.size()) // should never happen
				{
					g_logger.log("Socket handler (" + m_id + ") response ended with unprocessed data, "
								 "clearing and sending new request ... ", sinsp_logger::SEV_WARNING);
					ASSERT(!m_data_buf.size());
					m_data_buf.clear();
				}
				// In HTTP 1.1 connnections with chunked transfer, this socket may never be closed by server,
				// (K8s API server is an example of such behavior), in which case the chunked data will just
				// stop flowing. We can keep the good socket and resend the request instead of severing the
				// connection. The m_wants_send flag has to be checked by the caller and request re-sent, otherwise
				// this pipeline will remain idle. To force client-initiated socket close on chunked transfer end,
				// set the m_close_on_chunked_end flag to true (default).
				if(m_close_on_chunked_end)
				{
					g_logger.log("Socket handler (" + m_id + ") chunked response ended",
						     sinsp_logger::SEV_DEBUG);
					return CONNECTION_CLOSED;
				}
				m_wants_send = true;
				if(reinit) { init_http_parser(); }
			}
		}
		return 0;
	}

	int on_data()
	{
		bool is_error = false;

		if(!m_json_callback)
		{
			throw sinsp_exception("Socket handler (" + m_id + "): cannot parse data (callback is null).");
		}

		ssize_t iolen = 0;
		size_t len_read = 0, len_to_read = m_buf.size();
		try
		{
			do
			{
				if(len_read >= m_data_limit) { break; }
				else if((len_read + m_buf.size()) > m_data_limit)
				{
					len_to_read = m_data_limit - len_read;
				}
				errno = 0;
				if(m_url.is_secure())
				{
					iolen = static_cast<ssize_t>(SSL_read(m_ssl_connection, &m_buf[0], len_to_read));
				}
				else
				{
					iolen = recv(m_socket, &m_buf[0], len_to_read, 0);
				}
				if(iolen > 0) { len_read += iolen; }
				m_sock_err = errno;
				sinsp_logger::severity sev = (iolen < 0 && m_sock_err != EAGAIN) ?
					sinsp_logger::SEV_DEBUG : sinsp_logger::SEV_TRACE;
				g_logger.log("Socket handler (" + m_id + ") " + m_url.to_string(false) + ", iolen=" +
					     std::to_string(iolen) + ", data=" + std::to_string(len_read) + " bytes, "
					     "errno=" + std::to_string(m_sock_err) + " (" + strerror(m_sock_err) + ')',
					     sev);
				/* uncomment to see raw HTTP stream data in trace logs
					if((iolen > 0) && g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
					{
						g_logger.log("Socket handler (" + m_id + "), data --->" + std::string(&m_buf[0], iolen) + "<--- data",
									 sinsp_logger::SEV_TRACE);
					}
				*/
				if(iolen > 0)
				{
					size_t len = (iolen <= static_cast<ssize_t>(m_buf.size())) ? static_cast<size_t>(iolen) : m_buf.size();
					if(CONNECTION_CLOSED == process(&m_buf[0], len))
					{
						return CONNECTION_CLOSED;
					}
				}
				else if(iolen == 0 || m_sock_err == ENOTCONN || m_sock_err == EPIPE)
				{
					if(m_url.is_secure())
					{
						if(m_ssl_connection)
						{
							int err = SSL_get_error(m_ssl_connection, iolen);
							if (err != SSL_ERROR_ZERO_RETURN)
							{
								g_logger.log("Socket handler(" + m_id + "): SSL conn closed with code "
									     + std::to_string(err),
									     sinsp_logger::SEV_DEBUG);
							}

							int sd = SSL_get_shutdown(m_ssl_connection);
							if(sd == 0)
							{
								g_logger.log("Socket handler (" + m_id + "): SSL zero bytes received, "
											 "but no shutdown state set for [" + m_url.to_string(false) + "]: ",
											 sinsp_logger::SEV_WARNING);
							}
							if(sd & SSL_RECEIVED_SHUTDOWN)
							{
								g_logger.log("Socket handler(" + m_id + "): SSL shutdown from [" +
											 m_url.to_string(false) + "]: ", sinsp_logger::SEV_TRACE);
							}
							if(sd & SSL_SENT_SHUTDOWN)
							{
								g_logger.log("Socket handler(" + m_id + "): SSL shutdown sent to [" +
											 m_url.to_string(false) + "]: ", sinsp_logger::SEV_TRACE);
							}
						}
						else
						{
							g_logger.log("Socket handler(" + m_id + "): SSL connection is null",
											 sinsp_logger::SEV_WARNING);
						}
					}
					goto connection_closed;
				}
				else if(iolen < 0)
				{
					if(m_sock_err == ENOTCONN || m_sock_err == EPIPE)
					{
						goto connection_closed;
					}
					else if(m_sock_err != EAGAIN && m_sock_err != EWOULDBLOCK)
					{
						goto connection_error;
					}
					if(m_url.is_secure())
					{
						int err = SSL_get_error(m_ssl_connection, iolen);
						if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
						{
							g_logger.log("Socket handler(" + m_id + "): received SSL error"
								     + std::to_string(err),
								     sinsp_logger::SEV_ERROR);
							goto connection_error;
						}
					}
				}
			} while(iolen && (m_sock_err != EAGAIN) && (len_read < m_data_limit));
			g_logger.log("Socket handler (" + m_id + ") " +
						 std::to_string(len_read) + " bytes of data received",
						 sinsp_logger::SEV_TRACE);
		}
		catch(const sinsp_exception& ex)
		{
			g_logger.log(std::string("Socket handler (" + m_id + ") data receive error [" +
						 m_url.to_string(false) + "]: ").append(ex.what()),
						 sinsp_logger::SEV_ERROR);
			return m_sock_err;
		}
		return 0;

	connection_error:
		is_error = true;

	connection_closed:
		if(m_url.is_secure())
		{
			std::string ssl_err = ssl_errors();
			if(!ssl_err.empty())
			{
				g_logger.log(ssl_err, sinsp_logger::SEV_ERROR);
			}
		}
		return is_error ? m_sock_err : CONNECTION_CLOSED;
	}

	void on_error(const std::string& /*err*/, bool /*disconnect*/)
	{
	}

	bool has_json_filter(const std::string& filter)
	{
		for(auto flt : m_json_filters)
		{
			if(flt == filter)
			{
				return true;
			}
		}
		return false;
	}

	void add_json_filter(const std::string& filter, const std::string& before_filter = "")
	{
		if(filter.empty())
		{
			throw sinsp_exception(std::string("Socket handler (") + m_id + "), "
							  "[" + m_url.to_string(false) + "] "
							  "attempt to add empty filter");
		}
		remove_json_filter(filter);
		if(before_filter.empty())
		{
			m_json_filters.push_back(filter);
			return;
		}
		else
		{
			auto it = m_json_filters.begin();
			for(; it != m_json_filters.end(); ++it)
			{
				if(*it == before_filter) { break; }
			}
			if(it == m_json_filters.end())
			{
				g_logger.log("Socket handler (" + m_id + "), [" + m_url.to_string(false) + "] "
							 "attempt to insert filter before a non-existing filter. "
							 "Filter will be added to the end of filter list.", sinsp_logger::SEV_WARNING);
			}
			m_json_filters.insert(it, filter);
		}
	}

	void remove_json_filter(const std::string& filter)
	{
		for(auto it = m_json_filters.begin(); it != m_json_filters.end(); ++it)
		{
			if(*it == filter)
			{
				m_json_filters.erase(it);
				return;
			}
		}
	}

	void replace_json_filter(const std::string& from, const std::string& to)
	{
		for(auto it = m_json_filters.begin(); it != m_json_filters.end(); ++it)
		{
			if(*it == from)
			{
				*it = to;
				return;
			}
		}
		throw sinsp_exception(std::string("Socket handler (") + m_id + "), "
							  "[" + m_url.to_string(false) + "] "
							  "attempt to replace non-existing filter");
	}

	void print_filters(sinsp_logger::severity sev = sinsp_logger::SEV_DEBUG)
	{
		std::ostringstream filters;
		filters << std::endl << "Filters:" << std::endl;
		for(auto filter : m_json_filters)
		{
			filters << filter << std::endl;
		}
		g_logger.log("Socket handler (" + m_id + "), [" + m_url.to_string(false) + "]" + filters.str(), sev);
	}

	static json_ptr_t try_parse(json_query& jq, const std::string& json, const std::string& filter,
				    const std::string& id, const std::string& url)
	{
		std::string filtered_json(json);
		if(!filter.empty())
		{
			// failure to parse is ok, it will fail over to the next filter
			// and log error if all filters fail
			if(jq.process(json, filter))
			{
				filtered_json = jq.result();
				if (filtered_json.empty() && !jq.get_error().empty())
				{
					g_logger.log("Socket handler (" + id + "), [" +
						     url + "] filter result is empty \"" +
						     jq.get_error() + "\"; JSON: <" +
						     json + ">, jq filter: <" + filter + '>',
						     sinsp_logger::SEV_DEBUG);
				}
			}
			else
			{
				g_logger.log("Socket handler (" + id + "), [" +
					     url + "] filter processing error \"" +
					     jq.get_error() + "\"; JSON: <" +
					     json + ">, jq filter: <" + filter + '>',
					     sinsp_logger::SEV_DEBUG);
				return nullptr;
			}
		}
		json_ptr_t root(new Json::Value());
		try
		{
			if(Json::Reader().parse(filtered_json, *root))
			{
				/*
				if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
				{
					g_logger.log("Socket handler (" + id + "), [" + url + "] "
								 "filtered JSON: " + json_as_string(*root),
								 sinsp_logger::SEV_TRACE);
				}
				*/
				return root;
			}
		}
		catch(...) { }
		g_logger.log("Socket handler (" + id + "), [" + url + "] parsing error; JSON: <" +
					 json + ">, jq filter: <" + filter + '>', sinsp_logger::SEV_ERROR);
		return nullptr;
	}

	// when connection is non-blocking and a socket
	// should not be polled until it is connected
	// this flag indicates readiness to be polled
	bool is_enabled() const
	{
		return m_enabled;
	}

	void enable(bool e = true)
	{
		m_enabled = e;
	}

	bool connection_error() const
	{
		return m_connection_error;
	}

	int get_socket_error()
	{
		socklen_t optlen = sizeof(m_sock_err);
		int ret = getsockopt(m_socket, SOL_SOCKET, SO_ERROR, &m_sock_err, &optlen);
		g_logger.log("Socket handler (" + m_id + ") getsockopt() ret=" +
						 std::to_string(ret) + ", m_sock_err=" + std::to_string(m_sock_err) +
						 " (" + strerror(m_sock_err) + ')',
						 sinsp_logger::SEV_TRACE);
		if(!ret) { return m_sock_err; }
		throw sinsp_exception("Socket handler (" + m_id + ") an error occurred "
					 "trying to obtain socket status while connecting to " +
					 m_url.to_string(false) + ": " + strerror(ret));
	}

private:

	typedef std::vector<char> password_vec_t;

	int wait(bool for_recv, long tout = 1000L)
	{
		struct timeval tv;
		tv.tv_sec = m_timeout_ms / 1000;
		tv.tv_usec = (m_timeout_ms % 1000) * 1000;

		fd_set infd, outfd, errfd;
		FD_ZERO(&infd);
		FD_ZERO(&outfd);
		FD_ZERO(&errfd);
		FD_SET(m_socket, &errfd);
		if(for_recv)
		{
			FD_SET(m_socket, &infd);
		}
		else
		{
			FD_SET(m_socket, &outfd);
		}

		return select(m_socket + 1, &infd, &outfd, &errfd, &tv);
	}

	bool send_ready()
	{
		struct timeval tv = {0};
		fd_set outfd;
		FD_ZERO(&outfd);
		FD_SET(m_socket, &outfd);
		int sel_ret = select(m_socket + 1, 0, &outfd, 0, &tv);
		if(sel_ret != 1) { return false; }
		int sock_ret = get_socket_error();
		if(!sock_ret) { return true; }
		return false;
	}

	bool recv_ready()
	{
		struct timeval tv = {0};
		fd_set infd;
		FD_ZERO(&infd);
		FD_SET(m_socket, &infd);
		return select(m_socket + 1, &infd, 0, 0, &tv) == 1;
	}

	bool socket_error()
	{
		struct timeval tv = {0};
		fd_set errfd;
		FD_ZERO(&errfd);
		FD_SET(m_socket, &errfd);
		return select(m_socket + 1, 0, 0, &errfd, &tv) == 1;
	}

	static int ssl_verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
	{
		SSL* ssl = (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
		if(ssl)
		{
			char  buf[256] = {0};
			X509* err_cert = X509_STORE_CTX_get_current_cert(ctx);
			X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

			if(preverify_ok && SSL_get_verify_result(ssl) == X509_V_OK)
			{
				g_logger.log("Socket handler SSL CA verified: " + std::string(buf),
							 sinsp_logger::SEV_DEBUG);
				return 1;
			}
			else
			{
				int err = X509_STORE_CTX_get_error(ctx);
				int depth = X509_STORE_CTX_get_error_depth(ctx);
				g_logger.log("Socket handler SSL CA verify error: num=" + std::to_string(err) +
							 ':' + X509_verify_cert_error_string(err) +
							 ":depth=" + std::to_string(depth) +
							 ':' + std::string(buf), sinsp_logger::SEV_ERROR);
				return 0;
			}
		}
		return 0;
	}

	static int ssl_no_verify_callback(int, X509_STORE_CTX* ctx)
	{
		g_logger.log("Socket handler SSL CA verification disabled, certificate accepted.",
					 sinsp_logger::SEV_DEBUG);
		return 1;
	}

	static int ssl_key_password_cb(char *buf, int size, int, void* pass)
	{
		if(pass)
		{
			std::memset(buf, 0, size);
			int pass_len = static_cast<int>(strlen((char*)pass));
			if(size < (pass_len) + 1) { return 0; }
			strncpy(buf, (const char*)pass, pass_len);
			return pass_len;
		}
		return 0;
	}

	std::string ssl_errors()
	{
		std::ostringstream os;
		if(m_url.is_secure())
		{
			char errbuf[256] = {0};
			unsigned long err;
			while((err = ERR_get_error()) != 0)
			{
				if(os.str().empty())
				{
					os << "Socket handler (" << m_id << ", "
						"socket=" << std::to_string(m_socket) << ") SSL errors:\n";
				}
				os << ERR_error_string(err, errbuf) << std::endl;
			}
		}
		return os.str();
	}

	void init_ssl_context(void)
	{
		if(!m_ssl_context)
		{
			SSL_library_init();
			SSL_load_error_strings();
			OpenSSL_add_all_algorithms();
			const SSL_METHOD* method =
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
				TLSv1_2_client_method();
#else
				TLS_client_method();
#endif
			if(!method)
			{
				g_logger.log("Socket handler (" + m_id + "): Can't initialize SSL method\n" + ssl_errors(),
							 sinsp_logger::SEV_ERROR);
			}
			m_ssl_context = SSL_CTX_new(method);
			if(!m_ssl_context)
			{
				g_logger.log("Socket handler (" + m_id + "): Can't initialize SSL context\n" + ssl_errors(),
							 sinsp_logger::SEV_ERROR);
				return;
			}

			if(m_ssl)
			{
				if(m_ssl->verify_peer())
				{
					const std::string ca_cert = m_ssl->ca_cert();
					if(!ca_cert.empty() && !SSL_CTX_load_verify_locations(m_ssl_context, ca_cert.c_str(), 0))
					{
						throw sinsp_exception("Socket handler (" + m_id + "): "
											  "Can't load SSL CA certificate (" + ca_cert + ").\n" +
											  ssl_errors());
					}
					else if(ca_cert.empty())
					{
						throw sinsp_exception("Socket handler (" + m_id + "): "
											  "Invalid SSL CA certificate configuration "
											  "(Verify Peer enabled but no CA certificate specified).");
					}
					SSL_CTX_set_verify(m_ssl_context, SSL_VERIFY_PEER, ssl_verify_callback);
					g_logger.log("Socket handler (" + m_id + "): CA verify set to PEER", sinsp_logger::SEV_TRACE);
				}
				else
				{
					SSL_CTX_set_verify(m_ssl_context, SSL_VERIFY_NONE, ssl_no_verify_callback);
					g_logger.log("Socket handler (" + m_id + "): CA verify set to NONE", sinsp_logger::SEV_TRACE);
				}

				const std::string& cert = m_ssl->cert();
				if(!cert.empty())
				{
					if(SSL_CTX_use_certificate_file(m_ssl_context, cert.c_str(), SSL_FILETYPE_PEM) <= 0)
					{
						throw sinsp_exception("Socket handler (" + m_id + "): "
											  "Can't load SSL certificate  from " + cert + ".\n" +
											  ssl_errors());
					}
					else
					{
						g_logger.log("Socket handler (" + m_id + "): using SSL certificate from " + cert,
									 sinsp_logger::SEV_TRACE);
					}
					const std::string& key = m_ssl->key();
					if(!key.empty())
					{
						const std::string& pass = m_ssl->key_passphrase();
						if(!pass.empty())
						{
							m_ssl_key_pass.assign(pass.begin(), pass.end());
							m_ssl_key_pass.push_back('\0');
							SSL_CTX_set_default_passwd_cb_userdata(m_ssl_context, (void*)&m_ssl_key_pass[0]);
							SSL_CTX_set_default_passwd_cb(m_ssl_context, ssl_key_password_cb);
						}

						if(SSL_CTX_use_PrivateKey_file(m_ssl_context, key.c_str(), SSL_FILETYPE_PEM) <= 0)
						{
							throw sinsp_exception("Socket handler (" + m_id + "): "
											  "Can't load SSL private key from " + key + ".\n" +
											  ssl_errors());
						}
						else
						{
							g_logger.log("Socket handler (" + m_id + "): using SSL private key from " + key, sinsp_logger::SEV_TRACE);
						}

						if(!SSL_CTX_check_private_key(m_ssl_context))
						{
							throw sinsp_exception("Socket handler (" + m_id + "): "
											  "SSL private key (" + key + ") does not match public certificate (" + cert + ").\n" +
											  ssl_errors());
						}
						else
						{
							g_logger.log("Socket handler (" + m_id + "): SSL private key " + key + " matches public certificate " + cert,
										 sinsp_logger::SEV_TRACE);
						}
					}
					else
					{
						throw sinsp_exception("Socket handler (" + m_id + "): "
											  "Invalid SSL configuration: public certificate specified without private key.");
					}
				}
				else
				{
					g_logger.log("Socket handler (" + m_id + "): SSL public certificate not provided.", sinsp_logger::SEV_TRACE);
				}
			}
		}
	}

	void init_ssl_socket()
	{
		if(m_socket != -1 && !m_ssl_init_complete)
		{
			if(m_url.is_secure())
			{
				if(!m_ssl_context) { init_ssl_context(); }
				if(m_ssl_context)
				{
					m_ssl_connection = SSL_new(m_ssl_context);
					if(m_ssl_connection)
					{
						if(1 == SSL_set_fd(m_ssl_connection, m_socket))
						{
							m_ssl_init_complete = true;
						}
						else
						{
							throw sinsp_exception("Socket handler " + m_id + " (" + m_url.to_string(false) + ") "
							  "error assigning socket to SSL connection: " + ssl_errors());
						}
					}
					else
					{
						throw sinsp_exception("Socket handler " + m_id + " (" + m_url.to_string(false) + ") "
							  "error obtaining socket: " + ssl_errors());
					}
				}
				else
				{
					throw sinsp_exception("Socket handler " + m_id + " (" + m_url.to_string(false) + ") "
						  "SSL context error : " + ssl_errors());
				}
			}
		}
	}

	void create_socket()
	{
		int sock_type = SOCK_STREAM;
		if(!m_blocking)
		{
			sock_type |= SOCK_NONBLOCK;
		}
		if(m_socket < 0)
		{
			if(m_url.is_file())
			{
				m_socket = socket(PF_UNIX, sock_type, 0);
			}
			else
			{
				m_socket = socket(PF_INET, sock_type, 0);
			}
			if(m_socket < 0)
			{
				throw sinsp_exception("Socket handler " + m_id + " (" + m_url.to_string(false) + ") "
									  "error obtaining socket: " + strerror(errno));
			}
		}
	}

	bool check_connected()
	{
		if(!send_ready())
		{
			if(m_sock_err && m_sock_err != EINPROGRESS)
			{
				m_connection_error = true;
				throw sinsp_exception("Socket handler (" + m_id + ") an error occurred "
							 "while connecting to " + m_url.to_string(false) + ": " + strerror(m_sock_err));
			}
			else if(m_sock_err == EINPROGRESS)
			{
				m_connection_error = false;
				m_connecting = true;
				m_connected = false;
			}
			return false;
		}
		return true;
	}

	bool try_connect()
	{
		g_logger.log("Socket handler (" + m_id + ") try_connect() entry, m_connecting=" + std::to_string(m_connecting) +
						 ", m_connected=" + std::to_string(m_connected), sinsp_logger::SEV_TRACE);
		if(m_connected) { return true; }
		if(m_socket == -1)
		{
			create_socket();
		}

		if(!is_resolved())
		{
			if(!try_resolve())
			{
				return false;
			}
		}

		int ret = -1;
		if(m_connection_error)
		{
			return false;
		}
		else
		{
			if(!check_connected())
			{
				return false;
			}
		}

		g_logger.log("Socket handler (" + m_id + ") try_connect() middle, m_connecting=" + std::to_string(m_connecting) +
						 ", m_connected=" + std::to_string(m_connected), sinsp_logger::SEV_TRACE);
		if(!m_connected)
		{
			g_logger.log("Socket handler (" + m_id + ") connecting to " + m_url.to_string(false) +
						 " (socket=" + std::to_string(m_socket) + ')', sinsp_logger::SEV_DEBUG);
			if(!m_sa || !m_sa_len)
			{
				std::ostringstream os;
				os << m_sa;
				throw sinsp_exception("Socket handler (" + m_id + ") invalid state connecting to " +
							 m_url.to_string(false) + " (socket=" + std::to_string(m_socket) + "), "
							 "sa=" + os.str() + ", sa_len=" + std::to_string(m_sa_len));
			}
			if(!m_connect_called)
			{
				ret = connect(m_socket, m_sa, m_sa_len);
				m_connect_called = true;
				if(ret < 0 && errno != EINPROGRESS)
				{
					throw sinsp_exception("Error during connection attempt to " + m_url.to_string(false) +
										  " (socket=" + std::to_string(m_socket) +
										  ", error=" + std::to_string(errno) + "): " + strerror(errno));
				}
				else if(errno == EINPROGRESS)
				{
					m_connecting = true;
					m_connected = false;
					return false;
				}
			}
			else
			{
				if(get_socket_error() == EINPROGRESS)
				{
					m_connecting = true;
					m_connected = false;
					return false;
				}
			}
			if(m_url.is_secure())
			{
				if(!m_ssl_init_complete)
				{
					init_ssl_socket();
				}
				if(m_ssl_connection)
				{
					ret = SSL_connect(m_ssl_connection);
					if(ret == 1)
					{
						m_connecting = false;
						m_connected = true;
						g_logger.log("Socket handler (" + m_id + "): "
									 "SSL connected to " + m_url.get_host(),
									 sinsp_logger::SEV_INFO);
						g_logger.log("Socket handler (" + m_id + "): "
									 "SSL socket=" + std::to_string(m_socket) + ", "
									 "local port=" + std::to_string(get_local_port()),
									 sinsp_logger::SEV_DEBUG);
					}
					else
					{
						int err = SSL_get_error(m_ssl_connection, ret);
						switch(err)
						{
						case SSL_ERROR_NONE:             // 0
							break;
						case SSL_ERROR_SSL:              // 1
							throw sinsp_exception(ssl_errors());
						case SSL_ERROR_WANT_READ:        // 2
						case SSL_ERROR_WANT_WRITE:       // 3
							return false;
						case SSL_ERROR_WANT_X509_LOOKUP: // 4
							break;
						case SSL_ERROR_SYSCALL:          // 5
							throw sinsp_exception("Socket handler (" + m_id + "), error "  + std::to_string(err) +
												  " (" + strerror(errno) + ") while connecting to " +
												  m_url.get_host() + ':' + std::to_string(m_url.get_port()));
						case SSL_ERROR_ZERO_RETURN:      // 6
							cleanup();
							throw sinsp_exception("Socket handler (" + m_id + "), "
												  "error (connection closed) while connecting to " +
												  m_url.get_host() + ':' + std::to_string(m_url.get_port()));
						case SSL_ERROR_WANT_CONNECT:     // 7
							throw sinsp_exception("Socket handler (" + m_id + "), "
												  "error (the operation failed while attempting to connect "
												  "the transport) while connecting to " +
												  m_url.get_host() + ':' + std::to_string(m_url.get_port()));
						case SSL_ERROR_WANT_ACCEPT:      // 8
							throw sinsp_exception("Socket handler (" + m_id + "), "
												  "error (the operation failed while attempting to accept a"
												  " connection from the transport) while connecting to " +
												  m_url.get_host() + ':' + std::to_string(m_url.get_port()));
						}
					}
				}
				else
				{
					throw sinsp_exception("Socket handler (" + m_id + "): " + m_url.to_string(false) +
										" SSL connection is null (" + strerror(errno) + ')');
				}
			}

			g_logger.log("Socket handler (" + m_id + "): Connected: socket=" + std::to_string(m_socket) +
						 ", collecting data from " + m_url.to_string(false) + m_path, sinsp_logger::SEV_DEBUG);

			if(m_url.is_secure() && m_ssl && m_ssl->verify_peer())
			{
				if(SSL_get_peer_certificate(m_ssl_connection))
				{
					long err = SSL_get_verify_result(m_ssl_connection);
					if(err != X509_V_OK &&
						err != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT &&
						err != X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
					{
						throw sinsp_exception("Socket handler (" + m_id + "): " + m_url.to_string(false) +
											  " server certificate verification failed.");
					}
				}
			}
			m_connection_error = false;
			m_connecting = false;
			m_connected = true;
		}
		return true;
	}

	bool is_resolved() const
	{
		return (!m_address.empty() && m_sa && m_sa_len) || m_url.is_file();
	}

	bool try_resolve()
	{
		if(is_resolved())
		{
			return true;
		}
		else
		{
			if(inet_aton(m_url.get_host().c_str(), &m_serv_addr.sin_addr)) // IP address provided
			{
				m_address = m_url.get_host();
			}
			else // name provided, resolve to IP address
			{
				m_serv_addr = {0};
				int ret = 0;
				if(!m_dns_reqs) // first call, call async resolver
				{
					g_logger.log("Socket handler (" + m_id + ") resolving " + m_url.get_host(),
								 sinsp_logger::SEV_TRACE);
					m_dns_reqs = make_gaicb(m_url.get_host());
					ret = getaddrinfo_a(GAI_NOWAIT, m_dns_reqs.get(), 1, NULL);
					if(ret)
					{
						throw sinsp_exception("Socket handler (" + m_id + "): " + m_url.get_host() +
									 " getaddrinfo_a() failed: " + gai_strerror(ret));
					}
					return false;
				}
				else // rest of the calls, try to get resolver result
				{
					g_logger.log("Socket handler (" + m_id + ") checking resolve for " + m_url.get_host(),
								 sinsp_logger::SEV_TRACE);
					ret = gai_error(m_dns_reqs[0]);
					g_logger.log("Socket handler (" + m_id + ") gai_error=" + std::to_string(ret),
								 sinsp_logger::SEV_TRACE);
					if(!ret)
					{
						if(m_dns_reqs && m_dns_reqs[0] && m_dns_reqs[0]->ar_result)
						{
							for (struct addrinfo* ai = m_dns_reqs[0]->ar_result; ai; ai = ai->ai_next)
							{
								if(ai->ai_addrlen && ai->ai_addr && ai->ai_addr->sa_family == AF_INET)
								{
									struct sockaddr_in* saddr = (struct sockaddr_in*)ai->ai_addr;
									if(saddr->sin_addr.s_addr)
									{
										m_serv_addr.sin_addr.s_addr = saddr->sin_addr.s_addr;
										m_address = inet_ntoa(saddr->sin_addr);
										g_logger.log("Socket handler (" + m_id + "): " + m_url.get_host() +
													 " resolved to " + m_address, sinsp_logger::SEV_TRACE);
										dns_cleanup();
										break;
									}
								}
							}
							if(!m_serv_addr.sin_addr.s_addr)
							{
								g_logger.log("Socket handler (" + m_id + "): " + m_url.get_host() +
											 " address not resolved yet.", sinsp_logger::SEV_TRACE);
								return false;
							}
						}
						else
						{
							throw sinsp_exception("Socket handler (" + m_id + "): " + m_url.get_host() +
												  ", resolver request is NULL.");
						}
					}
					else
					{
						switch(ret)
						{
							case EAI_AGAIN:
							case EAI_INPROGRESS:
								g_logger.log("Socket handler (" + m_id + ") [" + m_url.get_host() + "]: " +
											 gai_strerror(ret), sinsp_logger::SEV_DEBUG);
								break;
							case EAI_SYSTEM:
								g_logger.log("Socket handler (" + m_id + ") [" + m_url.get_host() + "]: " +
											 ", resolver error: " + gai_strerror(ret) +
											 ", system error: " + strerror(errno), sinsp_logger::SEV_ERROR);
								break;
							default:
								g_logger.log("Socket handler (" + m_id + ") [" + m_url.get_host() + "]: " +
											 ", resolver error: " + gai_strerror(ret),
											 sinsp_logger::SEV_ERROR);
						}
						return false;
					}
				}
			}
		}
		m_serv_addr.sin_family = AF_INET;
		m_serv_addr.sin_port = htons(m_url.get_port());
		m_sa = (sockaddr*)&m_serv_addr;
		m_sa_len = sizeof(struct sockaddr_in);
		return true;
	}

	void connect_socket()
	{
		if(!m_sa || !m_sa_len)
		{
			if(m_url.is_file())
			{
				if(m_url.get_path().length() > sizeof(m_file_addr.sun_path) - 1)
				{
					throw sinsp_exception("Invalid address (too long): [" + m_url.get_path() + ']');
				}
				m_file_addr.sun_family = AF_UNIX;
				strncpy(m_file_addr.sun_path, m_url.get_path().c_str(), m_url.get_path().length());
				m_file_addr.sun_path[sizeof(m_file_addr.sun_path) - 1]= '\0';
				m_sa = (sockaddr*)&m_file_addr;
				m_sa_len = sizeof(struct sockaddr_un);
			}
			else if(m_url.is("https") || m_url.is("http"))
			{
				try_resolve();
			}
			else
			{
				throw sinsp_exception("Socket handler (" + m_id + "): " +
									  m_url.get_scheme() + " protocol not supported.");
			}
		}
		try_connect();
	}

	std::string get_local_address()
	{
		struct sockaddr_in local_address;
		socklen_t address_length = sizeof(local_address);
		getsockname(m_socket, (struct sockaddr*)&local_address, &address_length);
		return std::string(inet_ntoa(local_address.sin_addr));
	}

	int get_local_port()
	{
		struct sockaddr_in local_address;
		socklen_t address_length = sizeof(local_address);
		getsockname(m_socket, (struct sockaddr*)&local_address, &address_length);
		return (int) ntohs(local_address.sin_port);
	}

	void close_socket()
	{
		if(m_socket != -1)
		{
			g_logger.log("Socket handler (" + m_id + ") closing connection to " +
						 m_url.to_string(false) + m_path, sinsp_logger::SEV_DEBUG);
			int ret = close(m_socket);
			if(ret < 0)
			{
				g_logger.log("Socket handler (" + m_id + ") connection [" +
							 m_url.to_string(false) + m_path + "] error closing socket: " +
							 strerror(errno), sinsp_logger::SEV_ERROR);
			}
			m_socket = -1;
		}
		m_enabled = false;
		m_connected = false;
		m_connecting = false;
		m_connect_called = true;
	}

	bool dns_req_done(struct gaicb** dns_reqs) const
	{
		if(dns_reqs && dns_reqs[0])
		{
			int ret = gai_cancel(dns_reqs[0]);
			int err = gai_error(dns_reqs[0]);
			if(ret == EAI_ALLDONE || err == EAI_CANCELED)
			{
				return true;
			}
			else if(err == EAI_INPROGRESS || err == EAI_AGAIN)
			{
				std::string errstr = (err == EAI_INPROGRESS ) ?
									"processing in progress" :
									"resources temporarily unavailable";
				g_logger.log("Socket handler (" + m_id + ") connection [" + m_url.to_string(false) + "], "
							 " cancelling DNS request postponed (" + errstr + ")"
							 "\n err: (" + std::to_string(err) + ") " + gai_strerror(err),
							 sinsp_logger::SEV_DEBUG);
				return false;
			}
			else
			{
				g_logger.log("Socket handler (" + m_id + ") connection [" + m_url.to_string(false) + "], "
							 "error canceling DNS request"
							 "\n ret: (" + std::to_string(ret) + ") " + gai_strerror(ret) +
							 "\n err: (" + std::to_string(err) + ") " + gai_strerror(err),
							 sinsp_logger::SEV_ERROR);
				return false;
			}
		}
		return true;
	}

	void dns_cleanup()
	{
		for(dns_list_t::iterator it = m_pending_dns_reqs.begin(); it != m_pending_dns_reqs.end();)
		{
			if(dns_req_done(it->get()))
			{
				it = m_pending_dns_reqs.erase(it);
				g_logger.log("Socket handler: postponed canceling of DNS request succeeded, number of pending "
							 "cancellation requests: " + std::to_string(m_pending_dns_reqs.size()),
							 sinsp_logger::SEV_TRACE);
			}
			else { ++it; }
		}

		std::size_t pending_reqs = m_pending_dns_reqs.size();
		if(pending_reqs)
		{
			g_logger.log("Socket handler: number of pending DNS cancellation requests is " + std::to_string(pending_reqs),
						 (pending_reqs > 10) ? sinsp_logger::SEV_WARNING : sinsp_logger::SEV_TRACE);
		}

		if(!dns_req_done(m_dns_reqs.get()))
		{
			m_pending_dns_reqs.emplace_back(std::move(m_dns_reqs));
		}
		m_dns_reqs = nullptr;
	}

	void ssl_cleanup()
	{
		SSL_free(m_ssl_connection);
		m_ssl_connection = 0;
		SSL_CTX_free(m_ssl_context);
		m_ssl_context = 0;
	}

	void cleanup()
	{
		free(m_http_parser);
		m_http_parser = nullptr;
		close_socket();
		dns_cleanup();
		ssl_cleanup();
	}

	struct http_parser_data
	{
		std::string* m_data_buf = nullptr;
		std::vector<std::string>* m_json = nullptr;
		int* m_http_response = nullptr;
		bool* m_msg_completed = nullptr;
		bool* m_fetching_state = nullptr;
	};

	static int http_body_callback(http_parser* parser, const char* data, size_t len)
	{
		if(parser)
		{
			if(parser->data)
			{
				if(data && len)
				{
					http_parser_data* parser_data = (http_parser_data*) parser->data;
					if(parser_data->m_data_buf && parser_data->m_json)
					{
						parser_data->m_data_buf->append(data, len);
						// only try to parse this JSON if we are certain it is not pretty-printed
						// since this logic relies on JSONs in the stream being delimited by newlines
						// (and having no newlines themselves), pretty-printed JSONs can not be
						// handled here, but must be handled in the http_msg_completed_callback()
						if(parser_data->m_fetching_state)
						{
							if(!*(parser_data->m_fetching_state))
							{
								std::string::size_type pos = parser_data->m_data_buf->find('\n');
								while(pos != std::string::npos)
								{
									parser_data->m_json->push_back(parser_data->m_data_buf->substr(0, pos));
									parser_data->m_data_buf->erase(0, pos + 1);
									pos = parser_data->m_data_buf->find('\n');
								}
							}
							/*else
							{
								if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
								{
									g_logger.log("Socket handler (http_body_callback) data received, will be parsed on response end:" +
												 *parser_data->m_data_buf, sinsp_logger::SEV_TRACE);
								}
							}*/
						}
					}
					else { throw sinsp_exception("Socket handler (http_body_callback): http or json buffer is null."); }
				}
			}
			else { throw sinsp_exception("Socket handler (http_body_callback) parser data is null."); }
		}
		else { throw sinsp_exception("Socket handler (http_body_callback): parser is null."); }
		return 0;
	}

	static int http_msg_completed_callback(http_parser* parser)
	{
		if(parser && parser->data)
		{
			http_parser_data* parser_data = (http_parser_data*) parser->data;
			if(parser_data->m_fetching_state)
			{
				if(*(parser_data->m_fetching_state))
				{
					std::string* buf = parser_data->m_data_buf;
					if(buf)
					{
						std::string::size_type pos = buf->rfind('\n');
						if(pos != std::string::npos)
						{
							buf->erase(std::remove_if(buf->begin(), buf->end(), [](char c){return c == '\n' || c == '\r';}), buf->end());
							parser_data->m_json->emplace_back(std::move(*buf));
							buf->clear();
						}
						else
						{
							g_logger.log("Initial state fetch completed, but no newline found!", sinsp_logger::SEV_ERROR);
						}
						*(parser_data->m_fetching_state) = false;
					}
					else { throw sinsp_exception("Socket handler (http_msg_completed_callback): parser data m_data_buf is null."); }
				}
			}
			else { throw sinsp_exception("Socket handler (http_msg_completed_callback): parser data m_data_buf is null."); }
			if(parser_data->m_msg_completed)
			{
				*(parser_data->m_msg_completed) = true;
			}
			else { throw sinsp_exception("Socket handler (http_msg_completed_callback): parser data m_msg_completed is null."); }
			if(parser_data->m_http_response)
			{
				*(parser_data->m_http_response) = parser->status_code;
			}
			else { throw sinsp_exception("Socket handler (http_msg_completed_callback): parser data m_http_response is null."); }
		}
		else { throw sinsp_exception("Socket handler (http_msg_completed_callback): parser or data null."); }
		return 0;
	}

	void init_http_parser()
	{
		m_msg_completed = false;
		m_http_response = -1;
		http_parser_settings_init(&m_http_parser_settings);
		m_http_parser_settings.on_body = http_body_callback;
		m_http_parser_settings.on_message_complete = http_msg_completed_callback;
		if(!m_http_parser)
		{
			m_http_parser = (http_parser *)std::malloc(sizeof(http_parser));
		}
		m_http_parser_data.m_data_buf = &m_data_buf;
		m_http_parser_data.m_json = &m_json;
		m_http_parser_data.m_http_response = &m_http_response;
		m_http_parser_data.m_msg_completed = &m_msg_completed;
		m_http_parser_data.m_fetching_state = &m_fetching_state;
		http_parser_init(m_http_parser, HTTP_RESPONSE);
		m_http_parser->data = &m_http_parser_data;
	}

	static std::string get_http_reason(int status)
	{
		return http_reason::get(status);
	}

	using gaicb_t = std::unique_ptr<struct gaicb* [], gaicb_free>;
	using dns_list_t = std::deque<gaicb_t>;

	gaicb_t make_gaicb(const std::string &host)
	{
		gaicb_t dns_reqs((struct gaicb**)calloc(1, sizeof(struct gaicb*)));
		dns_reqs[0] = (struct gaicb*)calloc(1, sizeof(struct gaicb));
		dns_reqs[0]->ar_name = strdup(m_url.get_host().c_str());
		return dns_reqs;
	}

	T&                       m_obj;
	std::string              m_id;
	uri                      m_url;
	std::string              m_keep_alive;
	std::string              m_path;
	std::string              m_address;
	bool                     m_connecting = false;
	bool                     m_connected = false;
	bool                     m_connect_called = false;
	bool                     m_connection_error = false;
	bool                     m_enabled = false;
	int                      m_socket = -1;
	bool                     m_blocking = false;
	std::vector<char>        m_buf;
	int                      m_sock_err = 0;
	gaicb_t m_dns_reqs = nullptr;
	static dns_list_t        m_pending_dns_reqs;
	ssl_ptr_t                m_ssl;
	bt_ptr_t                 m_bt;
	long                     m_timeout_ms;
	json_callback_func_t     m_json_callback = nullptr;
	std::string              m_data_buf;
	std::string              m_request;
	std::string              m_http_version;
	std::vector<std::string> m_json_filters;
	std::vector<std::string> m_json;
	json_query               m_jq;
	bool                     m_ssl_init_complete = false;
	SSL_CTX*                 m_ssl_context = nullptr;
	SSL*                     m_ssl_connection = nullptr;
	password_vec_t           m_ssl_key_pass;
	struct sockaddr_un       m_file_addr = {0};
	struct sockaddr_in       m_serv_addr = {0};
	struct sockaddr*         m_sa = 0;
	socklen_t                m_sa_len = 0;
	bool                     m_close_on_chunked_end = true;
	bool                     m_wants_send = false;
	int                      m_http_response = -1;
	bool                     m_msg_completed = false;
	http_parser_settings     m_http_parser_settings;
	http_parser*             m_http_parser = nullptr;
	http_parser_data         m_http_parser_data;
	unsigned                 m_data_limit = 524288; // bytes

	// older versions of kubernetes send pretty-printed JSON by default;
	// that creates a problem with JSON-newline-delimit-based detection logic,
	// which relies on JSON itself having no newlines; while there is a way to
	// prevent this for entities (eg. nodes, pods) URIs by specifying '?pretty=false',
	// some cluster-level URIs (eg. /api) do not honor this parameter;
	//
	// this flag is true by default and it remains true until the first state http
	// request for this handler is completed, at which point all newlines are purged
	// from the string and the purged buffer is posted for further processing
	bool                     m_fetching_state = true;
};

template <typename T>
const std::string socket_data_handler<T>::HTTP_VERSION_10 = "1.0";
template <typename T>
const std::string socket_data_handler<T>::HTTP_VERSION_11 = "1.1";
template <typename T>
typename socket_data_handler<T>::dns_list_t socket_data_handler<T>::m_pending_dns_reqs;

#endif // HAS_CAPTURE
