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
// uri.cpp
//
// URI utility
//

#include "uri.h"
#include "sinsp.h"
#include <sstream>
#include <iomanip>

const std::string uri::SPECIAL_CHARS = "!#$&'()*+,/:;=?@[]";
const std::string uri::AMBIGUOUS_CHARS = " \"%-.<>\\^_`{|}~";

uri::uri(std::string str)
{
	trim(str);
	// parser does not handle missing host properly
	bool no_host = false;
	if(ci_find_substr(str, std::string("file:///")) == 0)
	{
		str.insert(7, "localhost");
		no_host = true;
	}
	parsed_uri p_uri = parse_uri(str.c_str());
	if(p_uri.error)
	{
		str = std::string("Invalid URI: [").append(str).append(1, ']');
		throw sinsp_exception(str);
	}
	m_scheme = str.substr(p_uri.scheme_start, p_uri.scheme_end - p_uri.scheme_start);
	std::transform(m_scheme.begin(), m_scheme.end(), m_scheme.begin(), ::tolower);
	if(!no_host)
	{
		m_host = str.substr(p_uri.host_start, p_uri.host_end - p_uri.host_start);
		std::transform(m_host.begin(), m_host.end(), m_host.begin(), ::tolower);
	}
	m_port = p_uri.port;
	if(m_port == 0)
	{
		m_has_port = false;
		m_port = get_well_known_port();
	}
	m_path = str.substr(p_uri.path_start, p_uri.path_end - p_uri.path_start);
	m_query = str.substr(p_uri.query_start, p_uri.query_end - p_uri.query_start);
	if(p_uri.user_info_end != p_uri.user_info_start)
	{
		std::string auth = str.substr(p_uri.user_info_start, p_uri.user_info_end - p_uri.user_info_start);
		std::string::size_type pos = auth.find(':');
		if(pos == std::string::npos)
		{
			throw sinsp_exception("Invalid credentials format.");
		}
		m_user = auth.substr(0, pos);
		m_password = auth.substr(pos + 1);
	}
}

void uri::check(std::string str)
{
	trim(str);
	// parser does not handle missing host properly
	if(ci_find_substr(str, std::string("file:///")) == 0)
	{
		str.insert(7, "localhost");
	}
	parsed_uri p_uri = parse_uri(str.c_str());
	if(p_uri.error)
	{
		str = std::string("Invalid URI: [").append(str).append(1, ']');
		throw sinsp_exception(str);
	}

	if(p_uri.user_info_end != p_uri.user_info_start)
	{
		std::string auth = str.substr(p_uri.user_info_start, p_uri.user_info_end - p_uri.user_info_start);
		std::string::size_type pos = auth.find(':');
		if(pos == std::string::npos)
		{
			throw sinsp_exception("Invalid credentials format.");
		}
	}
}

int uri::get_well_known_port() const
{
	if (!m_scheme.empty())
	{
		if(m_scheme == "http")        { return 80;   }
		else if(m_scheme == "file")   { return 0;    }
		else if(m_scheme == "https")  { return 443;  }
		else if(m_scheme == "ftp")    { return 21;   }
		else if(m_scheme == "ssh")    { return 22;   }
		else if(m_scheme == "telnet") { return 23;   }
		else if(m_scheme == "nntp")   { return 119;  }
		else if(m_scheme == "ldap")   { return 389;  }
		else if(m_scheme == "rtsp")   { return 554;  }
		else if(m_scheme == "sip")    { return 5060; }
		else if(m_scheme == "sips")   { return 5061; }
		else if(m_scheme == "xmpp")   { return 5222; }
	}
	return 0;
}

void uri::set_path(const std::string& path)
{
	uri u(*this);
	u.m_path = path;
	parsed_uri p_uri = parse_uri(u.to_string().c_str());
	if(p_uri.error)
	{
		throw sinsp_exception(std::string("Invalid URI Path: [").append(path).append(1, ']'));
	}
	m_path = path;
}

std::string uri::to_string(bool show_creds) const
{
	std::ostringstream ostr;
	ostr << m_scheme << "://";
	if(!m_user.empty())
	{
		if(show_creds)
		{
			ostr << m_user << ':' << m_password << '@';
		}
		else
		{
			ostr << "***:***@";
		}
	}
	ostr << m_host;
	if(m_port && m_has_port)
	{
		ostr << ':' << m_port;
	}
	ostr << m_path;
	if(!m_query.empty())
	{
		ostr << '?' << m_query;
	}
	return ostr.str();
}

std::string uri::encode(const std::string& str, const std::string& reserved)
{
	std::string encoded_str;
	for (std::string::const_iterator it = str.begin(); it != str.end(); ++it)
	{
		char c = *it;
		if((c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9'))
		{
			encoded_str += c;
		}
		else if (c <= 0x20 || c >= 0x7F ||
				 SPECIAL_CHARS.find(c) != std::string::npos ||
				 AMBIGUOUS_CHARS.find(c) != std::string::npos ||
				 reserved.find(c) != std::string::npos)
		{
			std::ostringstream ostr;
			ostr << "%" << std::setfill('0') << std::setw(2) << std::uppercase << std::hex << ((unsigned) (unsigned char) c);
			encoded_str.append(ostr.str());
		}
		else
		{
			encoded_str += c;
		}
	}
	return encoded_str;
}

// URI-decodes the given string by replacing percent-encoded
// characters with the actual character. Returns the decoded string.
//
// When plus_as_space is true, non-encoded plus signs in the query are decoded as spaces.
// (http://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1)
std::string uri::decode(const std::string& str, bool plus_as_space)
{
	std::string decoded_str;
	bool in_query = false;
	std::string::const_iterator it  = str.begin();
	std::string::const_iterator end = str.end();
	while(it != end)
	{
		char c = *it++;
		if(c == '?')
		{
			in_query = true;
		}
		// spaces may be encoded as plus signs in the query
		if(in_query && plus_as_space && c == '+')
		{
			c = ' ';
		}
		else if(c == '%')
		{
			if (it == end)
			{
				throw sinsp_exception("URI encoding: no hex digit following percent sign in " + str);
			}
			char hi = *it++;
			if (it == end)
			{
				throw sinsp_exception("URI encoding: two hex digits must follow percent sign in " + str);
			}
			char lo = *it++;
			if (hi >= '0' && hi <= '9')
			{
				c = hi - '0';
			}
			else if (hi >= 'A' && hi <= 'F')
			{
				c = hi - 'A' + 10;
			}
			else if (hi >= 'a' && hi <= 'f')
			{
				c = hi - 'a' + 10;
			}
			else
			{
				throw sinsp_exception("URI encoding: not a hex digit found in " + str);
			}
			c *= 16;
			if (lo >= '0' && lo <= '9')
			{
				c += lo - '0';
			}
			else if (lo >= 'A' && lo <= 'F')
			{
				c += lo - 'A' + 10;
			}
			else if (lo >= 'a' && lo <= 'f')
			{
				c += lo - 'a' + 10;
			}
			else
			{
				throw sinsp_exception("URI encoding: not a hex digit");
			}
		}
		decoded_str += c;
	}
	return decoded_str;
}

bool uri::is(const std::string& proto)
{
	return ci_compare::is_equal(m_scheme, proto);
}
