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
// sinsp_auth.cpp
//
// Authentication/verification utilities
//

#if defined(__linux__)

#include "sinsp_auth.h"
#include <fstream>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

//
// sinsp_ssl
//

sinsp_ssl::sinsp_ssl(const std::string& cert, const std::string& key, const std::string& key_passphrase,
	const std::string& ca_cert, bool verify_peer, const std::string& cert_type):
		m_cert_type(cert_type), m_cert(cert), m_key(key), m_key_passphrase(key_passphrase),
		m_ca_cert(ca_cert), m_verify_peer(verify_peer)
{
}

sinsp_ssl::~sinsp_ssl()
{
}

std::string sinsp_ssl::memorize_file(const std::string& disk_file)
{
	std::string mem_file;
	if(disk_file.empty())
	{
		return mem_file;
	}
	std::string::size_type pos = disk_file.rfind('/');
	if(pos == std::string::npos)
	{
		mem_file.append(1, '/').append(disk_file);
	}
	else
	{
		mem_file.append(disk_file.substr(pos, disk_file.size() - pos));
	}
	mem_file.append(1, '~');
	int fd = shm_open(mem_file.c_str(), O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
	if(fd != -1)
	{
		char buf[FILENAME_MAX] = { 0 };
		std::ifstream ifs(disk_file);
		std::string fd_path = "/proc/self/fd/" + std::to_string(fd);
		ssize_t sz = readlink(fd_path.c_str(), buf, sizeof(buf));
		if(sz != -1 && sz <= static_cast<ssize_t>(sizeof(buf)))
		{
			mem_file.assign(buf, sz);
			std::string str;
			std::ofstream ofs(mem_file, std::ofstream::out);
			while(std::getline(ifs, str))
			{
				ofs << str << '\n';
			}
		}
		else
		{
			std::ostringstream os;
			os << "Error occurred while trying to determine the real path of memory file [" << fd_path << "]: "
				<< strerror(errno) << " (disk file [" << disk_file << "] will be used).";
			g_logger.log(os.str(), sinsp_logger::SEV_WARNING);
			return disk_file;
		}
	}
	else
	{
		std::ostringstream os;
		os << "Memory file creation error: " << strerror(errno) << " (disk file [" << disk_file << "] will be used).";
		g_logger.log(os.str(), sinsp_logger::SEV_WARNING);
		return disk_file;
	}
	return mem_file;
}

void sinsp_ssl::unmemorize_file(const std::string& mem_file)
{
	if(shm_unlink(mem_file.c_str()) == 0)
	{
		std::ostringstream os;
		os << "Memory file [" << mem_file << "] unlink error: " << strerror(errno);
		g_logger.log(os.str(), sinsp_logger::SEV_WARNING);
	}
}

//
// bearer_token
//

sinsp_bearer_token::sinsp_bearer_token(const std::string& bearer_token_file, bool curl_support):
	m_bearer_token(stringize_file(bearer_token_file)), m_bt_auth_header(nullptr)
{
	if(curl_support)
	{
		std::size_t len = m_bearer_token.length(); // curl does not tolerate newlines in headers
		while(len && (m_bearer_token[len-1] == '\r' || m_bearer_token[len-1] == '\n'))
		{
			m_bearer_token.erase(len-1);
			len = m_bearer_token.length();
		}
		if(len)
		{
			std::string hdr = "Authorization: Bearer ";
			hdr.append(m_bearer_token);
			m_bt_auth_header = curl_slist_append(m_bt_auth_header, hdr.c_str());
		}
	}
}

sinsp_bearer_token::~sinsp_bearer_token()
{
	if(m_bt_auth_header)
	{
		curl_slist_free_all(m_bt_auth_header);
	}
}

std::string sinsp_bearer_token::stringize_file(const std::string& disk_file)
{
	std::string tmp, content;
	std::ifstream ifs(disk_file);
	while(std::getline(ifs, tmp))
	{
		content.append(tmp).append(1, '\n');
	}
	return content;
}

#endif // __linux__
