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

#include "http_reason.h"

const std::map<int, std::string> http_reason::m_http_reason =
	  { { 100, "Continue" },
		{ 101, "Switching Protocols" },
		{ 102, "Processing" },
		{ 200, "OK" },
		{ 201, "Created" },
		{ 202, "Accepted" },
		{ 203, "Non-Authoritative Information" },
		{ 204, "No Content" },
		{ 205, "Reset Content" },
		{ 206, "Partial Content" },
		{ 207, "Multi Status" },
		{ 208, "Already Reported" },
		{ 226, "IM Used" },
		{ 300, "Multiple Choices" },
		{ 301, "Moved Permanently" },
		{ 302, "Found" },
		{ 303, "See Other" },
		{ 304, "Not Modified" },
		{ 305, "Use Proxy" },
		{ 307, "Temporary Redirect" },
		{ 308, "Permanent Redirect" },
		{ 400, "Bad Request" },
		{ 401, "Unauthorized" },
		{ 402, "Payment Required" },
		{ 403, "Forbidden" },
		{ 404, "Not Found" },
		{ 405, "Method Not Allowed" },
		{ 406, "Not Acceptable" },
		{ 407, "Proxy Authentication Required" },
		{ 408, "Request Time-out" },
		{ 409, "Conflict" },
		{ 410, "Gone" },
		{ 411, "Length Required" },
		{ 412, "Precondition Failed" },
		{ 413, "Request Entity Too Large" },
		{ 414, "Request-URI Too Long" },
		{ 415, "Unsupported Media Type" },
		{ 416, "Requested Range Not Satisfiable" },
		{ 417, "Expectation Failed" },
		{ 418, "I'm a Teapot" },
		{ 420, "Enhance Your Calm" },
		{ 421, "Misdirected Request" },
		{ 422, "Unprocessable Entity" },
		{ 423, "Locked" },
		{ 424, "Failed Dependency" },
		{ 426, "Upgrade Required" },
		{ 428, "Precondition Required" },
		{ 429, "Too Many Requests" },
		{ 431, "Request Header Fields Too Large" },
		{ 451, "Unavailable For Legal Reasons" },
		{ 500, "Internal Server Error" },
		{ 501, "Not Implemented" },
		{ 502, "Bad Gateway" },
		{ 503, "Service Unavailable" },
		{ 504, "Gateway Time-Out" },
		{ 505, "HTTP Version Not Supported" },
		{ 506, "Variant Also Negotiates" },
		{ 507, "Insufficient Storage" },
		{ 508, "Loop Detected" },
		{ 510, "Not Extended" },
		{ 511, "Network Authentication Required" } };

std::string http_reason::get(int status)
{
	auto it = m_http_reason.find(status);
	if(it != m_http_reason.end())
	{
		return it->second;
	}
	return "";
}
