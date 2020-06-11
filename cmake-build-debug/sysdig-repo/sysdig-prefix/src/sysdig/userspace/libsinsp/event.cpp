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

#include "sinsp_errno.h"

#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <sys/socket.h>
#include <algorithm>
#else
#define NOMINMAX
#endif

#include <limits>

#include "sinsp.h"
#include "sinsp_int.h"

#include "../libscap/scap.h"

extern sinsp_evttables g_infotables;

#define SET_NUMERIC_FORMAT(resfmt, fmt, ostr, ustr, xstr) do {	\
	if(fmt == ppm_print_format::PF_OCT)                     \
	{                                                       \
		resfmt = (char*)"%#" ostr;                       \
	}                                                       \
	else if(fmt == ppm_print_format::PF_DEC)		\
	{                                                       \
		resfmt = (char*)"%" ustr;                       \
	}                                                       \
	else if(fmt == ppm_print_format::PF_10_PADDED_DEC)      \
	{                                                       \
		resfmt = (char*)"%09" ustr;                     \
	}                                                       \
	else if(fmt == ppm_print_format::PF_HEX)                \
	{                                                       \
		resfmt = (char*)"%" xstr;                       \
	}                                                       \
	else                                                    \
	{                                                       \
		resfmt = (char*)"%" ustr;                       \
	}                                                       \
} while(0)

///////////////////////////////////////////////////////////////////////////////
// sinsp_evt implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_evt::sinsp_evt() :
	m_pevt_storage(NULL),
	m_paramstr_storage(256), m_resolved_paramstr_storage(1024)
{
	m_flags = EF_NONE;
	m_tinfo = NULL;
#ifdef _DEBUG
	m_filtered_out = false;
#endif
	m_event_info_table = g_infotables.m_event_info;
}

sinsp_evt::sinsp_evt(sinsp *inspector) :
	m_pevt_storage(NULL),
	m_paramstr_storage(1024), m_resolved_paramstr_storage(1024)
{
	m_inspector = inspector;
	m_flags = EF_NONE;
	m_tinfo = NULL;
#ifdef _DEBUG
	m_filtered_out = false;
#endif
	m_event_info_table = g_infotables.m_event_info;
}

sinsp_evt::~sinsp_evt()
{
	if(m_pevt_storage)
	{
		delete[] m_pevt_storage;
	}
}

uint32_t sinsp_evt::get_dump_flags()
{
	return scap_event_get_dump_flags(m_inspector->m_h);
}

const char *sinsp_evt::get_name()
{
	return m_info->name;
}

event_direction sinsp_evt::get_direction()
{
	return (event_direction)(m_pevt->type & PPME_DIRECTION_FLAG);
}

int64_t sinsp_evt::get_tid()
{
	return m_pevt->tid;
}

void sinsp_evt::set_iosize(uint32_t size)
{
	m_iosize = size;
}

uint32_t sinsp_evt::get_iosize()
{
	return m_iosize;
}

sinsp_threadinfo* sinsp_evt::get_thread_info(bool query_os_if_not_found)
{
	if(NULL != m_tinfo)
	{
		return m_tinfo;
	}
	else if(m_tinfo_ref)
	{
		m_tinfo = m_tinfo_ref.get();

		return m_tinfo;
	}

	return m_inspector->get_thread(m_pevt->tid, query_os_if_not_found, false);
}

int64_t sinsp_evt::get_fd_num()
{
	if(m_fdinfo)
	{
		return m_tinfo->m_lastevent_fd;
	}
	else
	{
		return sinsp_evt::INVALID_FD_NUM;
	}
}


uint32_t sinsp_evt::get_num_params()
{
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	return (uint32_t)m_params.size();
}

sinsp_evt_param *sinsp_evt::get_param(uint32_t id)
{
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	return &(m_params[id]);
}

const char *sinsp_evt::get_param_name(uint32_t id)
{
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	ASSERT(id < m_info->nparams);

	return m_info->params[id].name;
}

const struct ppm_param_info* sinsp_evt::get_param_info(uint32_t id)
{
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	ASSERT(id < m_info->nparams);

	return &(m_info->params[id]);
}

uint32_t binary_buffer_to_hex_string(char *dst, char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	uint32_t j;
	uint32_t k;
	uint32_t l = 0;
	uint32_t num_chunks;
	uint32_t row_len;
	char row[128];
	char *ptr;
	bool truncated = false;

	for(j = 0; j < srclen; j += 8 * sizeof(uint16_t))
	{
		k = 0;
		k += sprintf(row + k, "\n\t0x%.4x:", j);

		ptr = &src[j];
		num_chunks = 0;
		while(num_chunks < 8 && ptr < src + srclen)
		{
			uint16_t chunk = htons(*(uint16_t*)ptr);

			if(ptr == src + srclen - 1)
			{
				k += sprintf(row + k, " %.2x", *(((uint8_t*)&chunk) + 1));
			}
			else
			{
				k += sprintf(row + k, " %.4x", chunk);
			}

			num_chunks++;
			ptr += sizeof(uint16_t);
		}

		if((fmt & sinsp_evt::PF_HEXASCII) || (fmt & sinsp_evt::PF_JSONHEXASCII))
		{
			// Fill the row with spaces to align it to other rows
			while(num_chunks < 8)
			{
				memset(row + k, ' ', 5);

				k += 5;
				num_chunks++;
			}

			row[k++] = ' ';
			row[k++] = ' ';

			for(ptr = &src[j];
				ptr < src + j + 8 * sizeof(uint16_t) && ptr < src + srclen;
				ptr++, k++)
			{
				if(isprint((int)(uint8_t)*ptr))
				{
					row[k] = *ptr;
				}
				else
				{
					row[k] = '.';
				}
			}
		}
		row[k] = 0;

		row_len = (uint32_t)strlen(row);
		if(l + row_len >= dstlen - 1)
		{
			truncated = true;
			break;
		}
		strcpy(dst + l, row);
		l += row_len;
	}

	dst[l++] = '\n';

	if(truncated)
	{
		return dstlen;
	}
	else
	{
		return l;
	}
}

uint32_t binary_buffer_to_asciionly_string(char *dst, char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	uint32_t j;
	uint32_t k = 0;

	if(fmt != sinsp_evt::PF_EOLS_COMPACT)
	{
		dst[k++] = '\n';
	}

	for(j = 0; j < srclen; j++)
	{
		//
		// Make sure there's enough space in the target buffer.
		// Note that we reserve two bytes, because some characters are expanded
		// when copied.
		//
		if(k >= dstlen - 1)
		{
			dst[k - 1] = 0;
			return dstlen;
		}

		if(isprint((int)(uint8_t)src[j]))
		{
			// switch(src[j])
			// {
			// case '"':
			// case '\\':
			// 	dst[k++] = '\\';
			// 	break;
			// default:
			// 	break;
			// }

			dst[k] = src[j];
			k++;
		}
		else if(src[j] == '\r')
		{
			dst[k] = '\n';
			k++;
		}
		else if(src[j] == '\n')
		{
			if(j > 0 && src[j - 1] != '\r')
			{
				dst[k] = src[j];
				k++;
			}
		}

	}

	return k;
}

uint32_t binary_buffer_to_string_dots(char *dst, char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	uint32_t j;
	uint32_t k = 0;

	for(j = 0; j < srclen; j++)
	{
		//
		// Make sure there's enough space in the target buffer.
		// Note that we reserve two bytes, because some characters are expanded
		// when copied.
		//
		if(k >= dstlen - 1)
		{
			dst[k - 1] = 0;
			return dstlen;
		}

		if(isprint((int)(uint8_t)src[j]))
		{
			// switch(src[j])
			// {
			// case '"':
			// case '\\':
			// 	dst[k++] = '\\';
			// 	break;
			// default:
			// 	break;
			// }

			dst[k] = src[j];
		}
		else
		{
			dst[k] = '.';
		}

		k++;
	}

	return k;
}

uint32_t binary_buffer_to_base64_string(char *dst, char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	//
	// base64 encoder, malloc-free version of:
	// http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
	//
	static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
		'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
		'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3',
		'4', '5', '6', '7', '8', '9', '+', '/'};
	static uint32_t mod_table[] = {0, 2, 1};

	uint32_t j,k, enc_dstlen;

	enc_dstlen = 4 * ((srclen + 2) / 3);
	//
	// Make sure there's enough space in the target buffer.
	//
	if(enc_dstlen >= dstlen - 1)
	{
		return dstlen;
	}

	for (j = 0, k = 0; j < srclen;) {

		uint32_t octet_a = j < srclen ? (unsigned char)src[j++] : 0;
		uint32_t octet_b = j < srclen ? (unsigned char)src[j++] : 0;
		uint32_t octet_c = j < srclen ? (unsigned char)src[j++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		dst[k++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		dst[k++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		dst[k++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		dst[k++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (j = 0; j < mod_table[srclen % 3]; j++)
		dst[enc_dstlen - 1 - j] = '=';

	return enc_dstlen;
}

uint32_t binary_buffer_to_json_string(char *dst, char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	uint32_t k = 0;
	switch(fmt)
	{
		case sinsp_evt::PF_JSONHEX:
		case sinsp_evt::PF_JSONHEXASCII:
			k = binary_buffer_to_hex_string(dst, src, dstlen, srclen, fmt);
			break;
		case sinsp_evt::PF_JSONEOLS:
			k =  binary_buffer_to_asciionly_string(dst, src, dstlen, srclen, fmt);
			break;
		case sinsp_evt::PF_JSONBASE64:
			k = binary_buffer_to_base64_string(dst, src, dstlen, srclen, fmt);
			break;
		default:
			k = binary_buffer_to_string_dots(dst, src, dstlen, srclen, fmt);
	}
	return k;
}

uint32_t binary_buffer_to_string(char *dst, char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	uint32_t k = 0;

	if(dstlen == 0)
	{
		ASSERT(false);
		return 0;
	}

	if(srclen == 0)
	{
		*dst = 0;
		return 0;
	}

	if(fmt & sinsp_evt::PF_HEX || fmt & sinsp_evt::PF_HEXASCII)
	{
		k = binary_buffer_to_hex_string(dst, src, dstlen, srclen, fmt);
	}
	else if(fmt & sinsp_evt::PF_BASE64)
	{
		k = binary_buffer_to_base64_string(dst, src, dstlen, srclen, fmt);
	}
	else if(fmt & sinsp_evt::PF_JSON  || fmt & sinsp_evt::PF_JSONHEX
			|| fmt & sinsp_evt::PF_JSONEOLS || fmt & sinsp_evt::PF_JSONHEXASCII
            || fmt & sinsp_evt::PF_JSONBASE64)
	{
		k = binary_buffer_to_json_string(dst, src, dstlen, srclen, fmt);
	}
	else if(fmt & (sinsp_evt::PF_EOLS | sinsp_evt::PF_EOLS_COMPACT))
	{
		k = binary_buffer_to_asciionly_string(dst, src, dstlen, srclen, fmt);
	}
	else
	{
		k = binary_buffer_to_string_dots(dst, src, dstlen, srclen, fmt);
	}

	dst[k] = 0;
	return k;
}

uint32_t strcpy_sanitized(char *dest, char *src, uint32_t dstsize)
{
	volatile char* tmp = (volatile char *)dest;
	uint32_t j = 0;
	g_invalidchar ic;

	while(j < dstsize)
	{
		if(!ic(*src))
		{
			*tmp = *src;
			tmp++;
			j++;
		}

		if(*src == 0)
		{
			*tmp = 0;
			return j + 1;
		}

		src++;
	}

	//
	// In case there wasn't enough space, null-terminate the destination
	//
	if(dstsize)
	{
		dest[dstsize - 1] = 0;
	}

	return dstsize;
}

int sinsp_evt::render_fd_json(Json::Value *ret, int64_t fd, const char** resolved_str, sinsp_evt::param_fmt fmt)
{
	sinsp_threadinfo* tinfo = get_thread_info();
	if(tinfo == NULL)
	{
		return 0;
	}

	if(fd >= 0)
	{
		sinsp_fdinfo_t *fdinfo = tinfo->get_fd(fd);
		if(fdinfo)
		{
			char tch = fdinfo->get_typechar();
			char ipprotoch = 0;

			if(fdinfo->m_type == SCAP_FD_IPV4_SOCK ||
				fdinfo->m_type == SCAP_FD_IPV6_SOCK ||
				fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK ||
				fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK)
			{
				scap_l4_proto l4p = fdinfo->get_l4proto();

				switch(l4p)
				{
				case SCAP_L4_TCP:
					ipprotoch = 't';
					break;
				case SCAP_L4_UDP:
					ipprotoch = 'u';
					break;
				case SCAP_L4_ICMP:
					ipprotoch = 'i';
					break;
				case SCAP_L4_RAW:
					ipprotoch = 'r';
					break;
				default:
					break;
				}
			}

			char typestr[3] =
			{
				(fmt & PF_SIMPLE)?(char)0:tch,
				ipprotoch,
				0
			};

			//
			// Make sure we remove invalid characters from the resolved name
			//
			string sanitized_str = fdinfo->m_name;

			sanitize_string(sanitized_str);

			(*ret)["typechar"] = typestr;
			(*ret)["name"] = sanitized_str;
		}
	}
	else if(fd == PPM_AT_FDCWD)
	{
		//
		// `fd` can be AT_FDCWD on all *at syscalls
		//
		(*ret)["name"] = "AT_FDCWD";
	}
	else
	{
		//
		// Resolve this as an errno
		//
		string errstr(sinsp_utils::errno_to_str((int32_t)fd));
		if(errstr != "")
		{
			(*ret)["error"] = errstr;
			return 0;
		}
	}

	return 1;
}

char* sinsp_evt::render_fd(int64_t fd, const char** resolved_str, sinsp_evt::param_fmt fmt)
{
	//
	// Add the fd number
	//
	snprintf(&m_paramstr_storage[0],
		        m_paramstr_storage.size(),
		        "%" PRId64, fd);

	sinsp_threadinfo* tinfo = get_thread_info();
	if(tinfo == NULL)
	{
		//
		// no thread. Definitely can't resolve the fd, just return the number
		//
		return &m_paramstr_storage[0];
	}

	if(fd >= 0)
	{
		sinsp_fdinfo_t *fdinfo = tinfo->get_fd(fd);
		if(fdinfo)
		{
			char tch = fdinfo->get_typechar();
			char ipprotoch = 0;

			if(fdinfo->m_type == SCAP_FD_IPV4_SOCK ||
				fdinfo->m_type == SCAP_FD_IPV6_SOCK ||
				fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK ||
				fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK)
			{
				scap_l4_proto l4p = fdinfo->get_l4proto();

				switch(l4p)
				{
				case SCAP_L4_TCP:
					ipprotoch = 't';
					break;
				case SCAP_L4_UDP:
					ipprotoch = 'u';
					break;
				case SCAP_L4_ICMP:
					ipprotoch = 'i';
					break;
				case SCAP_L4_RAW:
					ipprotoch = 'r';
					break;
				default:
					break;
				}
			}

			char typestr[3] =
			{
				(fmt & PF_SIMPLE)?(char)0:tch,
				ipprotoch,
				0
			};

			//
			// Make sure we remove invalid characters from the resolved name
			//
			string sanitized_str = fdinfo->m_name;

			sanitize_string(sanitized_str);

			//
			// Make sure the string will fit
			//
			if(sanitized_str.size() >= m_resolved_paramstr_storage.size())
			{
				m_resolved_paramstr_storage.resize(sanitized_str.size() + 1);
			}

			snprintf(&m_resolved_paramstr_storage[0],
				m_resolved_paramstr_storage.size(),
				"<%s>%s", typestr, sanitized_str.c_str());

/* XXX
			if(sanitized_str.length() == 0)
			{
				snprintf(&m_resolved_paramstr_storage[0],
							m_resolved_paramstr_storage.size(),
							"<%c>", tch);
			}
			else
			{
				snprintf(&m_resolved_paramstr_storage[0],
							m_resolved_paramstr_storage.size(),
							"%s", sanitized_str.c_str());
			}
*/
		}
	}
	else if(fd == PPM_AT_FDCWD)
	{
		//
		// `fd` can be AT_FDCWD on all *at syscalls
		//
		snprintf(&m_resolved_paramstr_storage[0],
				 m_resolved_paramstr_storage.size(),
				 "AT_FDCWD");
	}
	else
	{
		//
		// Resolve this as an errno
		//
		string errstr(sinsp_utils::errno_to_str((int32_t)fd));
		if(errstr != "")
		{
			snprintf(&m_resolved_paramstr_storage[0],
				        m_resolved_paramstr_storage.size(),
				        "%s", errstr.c_str());
		}
	}

	return &m_paramstr_storage[0];
}

Json::Value sinsp_evt::get_param_as_json(uint32_t id, OUT const char** resolved_str, sinsp_evt::param_fmt fmt)
{
	const ppm_param_info* param_info;
	char* payload;
	uint16_t payload_len;
	Json::Value ret;

	//
	// Make sure the params are actually loaded
	//
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	ASSERT(id < get_num_params());

	//
	// Reset the resolved string
	//
	m_resolved_paramstr_storage[0] = 0;

	//
	// Get the parameter
	//
	sinsp_evt_param *param = &(m_params[id]);
	payload = param->m_val;
	payload_len = param->m_len;
	param_info = &(m_info->params[id]);

	//
	// Get the parameter information
	//
	if(param_info->type == PT_DYN && param_info->info != NULL && payload_len != 0)
	{
		uint8_t dyn_idx = *(uint8_t*)payload;

		if(dyn_idx < param_info->ninfo) {
			const struct ppm_param_info* dyn_params =
				(const struct ppm_param_info*)param_info->info;

			payload += sizeof(uint8_t);
			payload_len -= sizeof(uint8_t);

			param_info = &dyn_params[dyn_idx];
		}
	}

	switch(param_info->type)
	{
	case PT_INT8:
		ASSERT(payload_len == sizeof(int8_t));
		ret = *(int8_t *)payload;
		break;

	case PT_INT16:
		ASSERT(payload_len == sizeof(int16_t));
		ret = *(int16_t *)payload;
		break;

	case PT_INT32:
		ASSERT(payload_len == sizeof(int32_t));
		ret = *(int32_t *)payload;
		break;

	case PT_INT64:
		ASSERT(payload_len == sizeof(int64_t));
		ret = (Json::Value::Int64)*(int64_t *)payload;
		break;

	case PT_UINT8:
		ASSERT(payload_len == sizeof(uint8_t));
		ret = *(uint8_t *)payload;
		break;

	case PT_UINT16:
		ASSERT(payload_len == sizeof(uint16_t));
		ret = *(uint16_t *)payload;
		break;

	case PT_UINT32:
		ASSERT(payload_len == sizeof(uint32_t));
		ret = *(uint32_t *)payload;
		break;

	case PT_UINT64:
		ASSERT(payload_len == sizeof(uint64_t));
		ret = (Json::Value::UInt64)*(int64_t *)payload;
		break;

	case PT_PID:
		{
			ASSERT(payload_len == sizeof(int64_t));
			ret = (Json::Value::UInt64)*(int64_t *)payload;

			sinsp_threadinfo* atinfo = m_inspector->get_thread(*(int64_t *)payload, false, true);
			if(atinfo != NULL)
			{
				string& tcomm = atinfo->m_comm;

				//
				// Make sure the string will fit
				//
				if(tcomm.size() >= m_resolved_paramstr_storage.size())
				{
					m_resolved_paramstr_storage.resize(tcomm.size() + 1);
				}

				snprintf(&m_resolved_paramstr_storage[0],
						 m_resolved_paramstr_storage.size(),
						 "%s",
						 tcomm.c_str());
			}
		}
		break;

	case PT_ERRNO:
	{
		ASSERT(payload_len == sizeof(int64_t));

		int64_t val = *(int64_t *)payload;

		//
		// Resolve this as an errno
		//
		string errstr;

		if(val < 0)
		{
			errstr = sinsp_utils::errno_to_str((int32_t)val);

			if(errstr != "")
			{
				snprintf(&m_resolved_paramstr_storage[0],
				         m_resolved_paramstr_storage.size(),
				         "%s", errstr.c_str());
			}
		}
		ret = (Json::Value::Int64)val;
	}
	break;

	case PT_FD:
		{
			// We use the string extractor to get
			// the resolved path, but use our routine
			// to get the actual value to return
			ASSERT(payload_len == sizeof(int64_t));
			int64_t fd = *(int64_t*)payload;
			render_fd_json(&ret, fd, resolved_str, fmt);
			ret["num"] = (Json::Value::UInt64)*(int64_t *)payload;
			break;
		}

	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_BYTEBUF:
		ret = get_param_as_str(id, resolved_str, fmt);
		break;

	case PT_SOCKADDR:
		if(payload_len == 0)
		{
			ret = Json::nullValue;
			break;
		}
		else if(payload[0] == AF_UNIX)
		{
			ASSERT(payload_len > 1);

			//
			// Sanitize the file string.
			//
			string sanitized_str = payload + 1;
			sanitize_string(sanitized_str);

			ret = sanitized_str;
		}
		else if(payload[0] == PPM_AF_INET)
		{
			if(payload_len == 1 + 4 + 2)
			{
				const int ipv4_len = (3 + 1) * 4 + 1;
				char ipv4_addr[ ipv4_len ];

				snprintf(
					ipv4_addr,
					ipv4_len,
						"%u.%u.%u.%u",
						(unsigned int)(uint8_t)payload[1],
						(unsigned int)(uint8_t)payload[2],
						(unsigned int)(uint8_t)payload[3],
						(unsigned int)(uint8_t)payload[4]
				);
				ret["addr"] = string(ipv4_addr);
				ret["port"] = *(uint16_t*)(payload + 5);
			}
			else
			{
				ASSERT(false);
				ret = "INVALID IPv4";
			}
		}
		else
		{
			ret["family"] = (int)payload[0];
		}
		break;

	case PT_SOCKTUPLE:
		if(payload_len == 0)
		{
			ret = Json::nullValue;
			break;
		}

		if(payload[0] == PPM_AF_INET)
		{
			if(payload_len == 1 + 4 + 2 + 4 + 2)
			{
				Json::Value source;
				Json::Value dest;

				const int ipv4_len = (3 + 1) * 4 + 1;
				char ipv4_addr[ ipv4_len ];

				snprintf(
					ipv4_addr,
					ipv4_len,
						"%u.%u.%u.%u",
						(unsigned int)(uint8_t)payload[1],
						(unsigned int)(uint8_t)payload[2],
						(unsigned int)(uint8_t)payload[3],
						(unsigned int)(uint8_t)payload[4]
				);

				source["addr"] = string(ipv4_addr);
				source["port"] = *(uint16_t*)(payload + 5);

				snprintf(
					ipv4_addr,
					ipv4_len,
				         "%u.%u.%u.%u",
				         (unsigned int)(uint8_t)payload[7],
				         (unsigned int)(uint8_t)payload[8],
				         (unsigned int)(uint8_t)payload[9],
				         (unsigned int)(uint8_t)payload[10]
				);


				dest["addr"] = string(ipv4_addr);
				dest["port"] = *(uint16_t*)(payload + 11);

				ret["src"] = source;
				ret["dst"] = dest;
			}
			else
			{
				ASSERT(false);
				ret = "INVALID IPv4";
			}
		}
		else if(payload[0] == PPM_AF_INET6)
		{
			if(payload_len == 1 + 16 + 2 + 16 + 2)
			{
				uint8_t* sip6 = (uint8_t*)payload + 1;
				uint8_t* dip6 = (uint8_t*)payload + 19;
				uint8_t* sip = (uint8_t*)payload + 13;
				uint8_t* dip = (uint8_t*)payload + 31;

				if(sinsp_utils::is_ipv4_mapped_ipv6(sip6) && sinsp_utils::is_ipv4_mapped_ipv6(dip6))
				{
					Json::Value source;
					Json::Value dest;

					const int ipv4_len = (3 + 1) * 4 + 1;
					char ipv4_addr[ ipv4_len ];

					snprintf(
						ipv4_addr,
						ipv4_len,
							"%u.%u.%u.%u",
							(unsigned int)sip[0],
							(unsigned int)sip[1],
							(unsigned int)sip[2],
							(unsigned int)sip[3]
					);

					source["addr"] = string(ipv4_addr);
					source["port"] = (unsigned int)*(uint16_t*)(payload + 17);

					snprintf(
						ipv4_addr,
						ipv4_len,
							"%u.%u.%u.%u",
							(unsigned int)dip[0],
							(unsigned int)dip[1],
							(unsigned int)dip[2],
							(unsigned int)dip[3]
				 	);

					dest["addr"] = string(ipv4_addr);
					dest["port"] = (unsigned int)*(uint16_t*)(payload + 35);

					ret["src"] = source;
					ret["dst"] = dest;

					break;
				}
				else
				{
					char srcstr[INET6_ADDRSTRLEN];
					char dststr[INET6_ADDRSTRLEN];

					if(inet_ntop(AF_INET6, sip6, srcstr, sizeof(srcstr)) &&
						inet_ntop(AF_INET6, dip6, dststr, sizeof(dststr)))
					{
						Json::Value source;
						Json::Value dest;

						source["addr"] = srcstr;
						source["port"] = (unsigned int)*(uint16_t*)(payload + 17);

						dest["addr"] = dststr;
						dest["port"] = (unsigned int)*(uint16_t*)(payload + 35);

						ret["src"] = source;
						ret["dst"] = dest;

						break;
					}
				}
			}
			ASSERT(false);
			ret = "INVALID IPv6";

		}
		else if(payload[0] == AF_UNIX)
		{
			ASSERT(payload_len > 17);

			//
			// Sanitize the file string.
			//
            string sanitized_str = payload + 17;
	    sanitize_string(sanitized_str);

			snprintf(&m_paramstr_storage[0],
				m_paramstr_storage.size(),
				"%" PRIx64 "->%" PRIx64 " %s",
				*(uint64_t*)(payload + 1),
				*(uint64_t*)(payload + 9),
				sanitized_str.c_str());
		}
		else
		{
			ret["family"] = (int)payload[0];
		}
		break;
	case PT_FDLIST:
		ret = get_param_as_str(id, resolved_str, fmt);
		break;

	case PT_SYSCALLID:
		{
			uint16_t scid = *(uint16_t *)payload;
			if(scid >= PPM_SC_MAX)
			{
				ASSERT(false);
				snprintf(&m_resolved_paramstr_storage[0],
						 m_resolved_paramstr_storage.size(),
						 "<unknown syscall>");
				break;
			}

			const struct ppm_syscall_desc* desc = &(g_infotables.m_syscall_info_table[scid]);

			ret = scid;

			snprintf(&m_resolved_paramstr_storage[0],
				m_resolved_paramstr_storage.size(),
				"%s",
				desc->name);
		}
		break;
	case PT_SIGTYPE:
		{
			const char* sigstr;

			ASSERT(payload_len == sizeof(uint8_t));
			uint8_t val = *(uint8_t *)payload;

			sigstr = sinsp_utils::signal_to_str(val);
			ret = val;

			if(sigstr)
			{
				snprintf(&m_resolved_paramstr_storage[0],
							m_resolved_paramstr_storage.size(),
							"%s", sigstr);
			}
		}
		break;
	case PT_RELTIME:
		{
			ASSERT(payload_len == sizeof(uint64_t));
			uint64_t val = *(uint64_t *)payload;
			ret = (Json::Value::Int64)val;

			snprintf(&m_resolved_paramstr_storage[0],
						m_resolved_paramstr_storage.size(),
						"%lgs",
						((double)val) / 1000000000);
		}
		break;
	case PT_FLAGS8:
	case PT_FLAGS16:
	case PT_FLAGS32:
		{
			uint32_t val = *(uint32_t *)payload & (((uint64_t)1 << payload_len * 8) - 1);
			ret["val"] = val;
			ret["flags"] = Json::arrayValue;

			const struct ppm_name_value *flags = (const struct ppm_name_value *)m_info->params[id].info;
			uint32_t initial_val = val;

			while(flags != NULL && flags->name != NULL && flags->value != initial_val)
			{
				// If flag is 0, then initial_val needs to be 0 for the flag to be resolved
				if((flags->value == 0 && initial_val == 0) ||
				   (flags->value != 0 && (val & flags->value) == flags->value && val != 0))
				{
					ret["flags"].append(flags->name);

					// We remove current flags value to avoid duplicate flags e.g. PPM_O_RDWR, PPM_O_RDONLY, PPM_O_WRONLY
					val &= ~flags->value;
				}

				flags++;
			}

			if(flags != NULL && flags->name != NULL)
			{
				ret["flags"].append(flags->name);
			}

			break;
		}
	case PT_MODE:
		{
			uint32_t val = *(uint32_t *)payload & (((uint64_t)1 << payload_len * 8) - 1);
			ret["val"] = val;
			ret["mode"] = Json::arrayValue;

			const struct ppm_name_value *mode = (const struct ppm_name_value *)m_info->params[id].info;
			uint32_t initial_val = val;

			while(mode != NULL && mode->name != NULL && mode->value != initial_val)
			{
				// If mode is 0, then initial_val needs to be 0 for the mode to be resolved
				if((mode->value == 0 && initial_val == 0) ||
				   (mode->value != 0 && (val & mode->value) == mode->value && val != 0))
				{
					ret["mode"].append(mode->name);

					// We remove current mode value to avoid duplicates
					val &= ~mode->value;
				}

				mode++;
			}

			if(mode != NULL && mode->name != NULL)
			{
				ret["mode"].append(mode->name);
			}

			break;
		}
	case PT_UID:
	case PT_GID:
	{
		ASSERT(payload_len == sizeof(uint32_t));
		uint32_t val = *(uint32_t *)payload;
		if(val < std::numeric_limits<uint32_t>::max() )
		{
			ret = val;
		}
		else
		{
			ret = -1;
		}
		break;
	}
	case PT_CHARBUFARRAY:
	{
		ASSERT(param->m_len == sizeof(uint64_t));
		vector<char*>* strvect = (vector<char*>*)*(uint64_t *)param->m_val;

		m_paramstr_storage[0] = 0;

		while(true)
		{
			vector<char*>::iterator it;
			vector<char*>::iterator itbeg;
			bool need_to_resize = false;

			//
			// Copy the arguments
			//
			char* dst = &m_paramstr_storage[0];
			char* dstend = &m_paramstr_storage[0] + m_paramstr_storage.size() - 2;

			for(it = itbeg = strvect->begin(); it != strvect->end(); ++it)
			{
				char* src = *it;

				if(it != itbeg)
				{
					if(dst < dstend - 1)
					{
						*dst++ = ',';
					}
				}

				while(*src != 0 && dst < dstend)
				{
					*dst++ = *src++;
				}

				if(dst == dstend)
				{
					//
					// Reached the end of m_paramstr_storage, we need to resize it
					//
					need_to_resize = true;
					break;
				}
			}

			if(need_to_resize)
			{
				m_paramstr_storage.resize(m_paramstr_storage.size() * 2);
				continue;
			}

			*dst = 0;

			break;
		}
	}
	break;
	case PT_CHARBUF_PAIR_ARRAY:
	{
		ASSERT(param->m_len == sizeof(uint64_t));
		pair<vector<char*>*, vector<char*>*>* pairs =
			(pair<vector<char*>*, vector<char*>*>*)*(uint64_t *)param->m_val;
		ASSERT(pairs->first->size() == pairs->second->size());

		m_paramstr_storage[0] = 0;

		while(true)
		{
			vector<char*>::iterator it1;
			vector<char*>::iterator itbeg1;
			vector<char*>::iterator it2;
			vector<char*>::iterator itbeg2;
			bool need_to_resize = false;

			//
			// Copy the arguments
			//
			char* dst = &m_paramstr_storage[0];
			char* dstend = &m_paramstr_storage[0] + m_paramstr_storage.size() - 2;

			for(it1 = itbeg1 = pairs->first->begin(), it2 = itbeg2 = pairs->second->begin();
			it1 != pairs->first->end();
				++it1, ++it2)
			{
				char* src = *it1;

				if(it1 != itbeg1)
				{
					if(dst < dstend - 1)
					{
						*dst++ = ',';
					}
				}

				//
				// Copy the first string
				//
				while(*src != 0 && dst < dstend)
				{
					*dst++ = *src++;
				}

				if(dst < dstend - 1)
				{
					*dst++ = ':';
				}

				//
				// Copy the second string
				//
				src = *it2;
				while(*src != 0 && dst < dstend)
				{
					*dst++ = *src++;
				}

				if(dst == dstend)
				{
					//
					// Reached the end of m_paramstr_storage, we need to resize it
					//
					need_to_resize = true;
					break;
				}
			}

			if(need_to_resize)
			{
				m_paramstr_storage.resize(m_paramstr_storage.size() * 2);
				continue;
			}

			*dst = 0;

			break;
		}
	}
	case PT_ABSTIME:
		//
		// XXX not implemented yet
		//
		ASSERT(false);
	case PT_DYN:
		ASSERT(false);
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "INVALID DYNAMIC PARAMETER");
		break;

	case PT_SIGSET:
		ret = get_param_as_str(id, resolved_str, fmt);
		break;

	default:
		ASSERT(false);
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "(n.a.)");
		break;
	}

	*resolved_str = &m_resolved_paramstr_storage[0];

	return ret;
}

const char* sinsp_evt::get_param_as_str(uint32_t id, OUT const char** resolved_str, sinsp_evt::param_fmt fmt)
{
	char* prfmt;
	const ppm_param_info* param_info;
	char* payload;
	uint32_t j;
	uint16_t payload_len;

	//
	// Make sure the params are actually loaded
	//
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	ASSERT(id < get_num_params());

	//
	// Reset the resolved string
	//
	m_resolved_paramstr_storage[0] = 0;

	//
	// Get the parameter
	//
	sinsp_evt_param *param = &(m_params[id]);
	payload = param->m_val;
	payload_len = param->m_len;
	param_info = &(m_info->params[id]);

	//
	// Get the parameter information
	//
	if(param_info->type == PT_DYN && param_info->info != NULL && payload_len != 0)
	{
		uint8_t dyn_idx = *(uint8_t*)payload;

		if(dyn_idx < param_info->ninfo) {
			const struct ppm_param_info* dyn_params =
				(const struct ppm_param_info*)param_info->info;

			payload += sizeof(uint8_t);
			payload_len -= sizeof(uint8_t);

			param_info = &dyn_params[dyn_idx];
		}
	}

	ppm_print_format param_fmt = m_info->params[id].fmt;

	switch(param_info->type)
	{
	case PT_INT8:
		ASSERT(payload_len == sizeof(int8_t));
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo8, PRId8, PRIX8);

		snprintf(&m_paramstr_storage[0],
			m_paramstr_storage.size(),
			prfmt, *(int8_t *)payload);
		break;
	case PT_INT16:
		ASSERT(payload_len == sizeof(int16_t));
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo16, PRId16, PRIX16);

		snprintf(&m_paramstr_storage[0],
			m_paramstr_storage.size(),
			prfmt, *(int16_t *)payload);
		break;
	case PT_INT32:
		ASSERT(payload_len == sizeof(int32_t));
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo32, PRId32, PRIX32);

		snprintf(&m_paramstr_storage[0],
			m_paramstr_storage.size(),
			prfmt, *(int32_t *)payload);
		break;
	case PT_INT64:
		ASSERT(payload_len == sizeof(int64_t));
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo64, PRId64, PRIX64);

		snprintf(&m_paramstr_storage[0],
			m_paramstr_storage.size(),
			prfmt, *(int64_t *)payload);
		break;
	case PT_FD:
		{
			ASSERT(payload_len == sizeof(int64_t));
			int64_t fd = *(int64_t*)payload;
			render_fd(fd, resolved_str, fmt);
			break;
		}
	case PT_PID:
		{
			ASSERT(payload_len == sizeof(int64_t));

			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%" PRId64, *(int64_t *)payload);


			sinsp_threadinfo* atinfo = m_inspector->get_thread(*(int64_t *)payload, false, true);
			if(atinfo != NULL)
			{
				string& tcomm = atinfo->m_comm;

				//
				// Make sure the string will fit
				//
				if(tcomm.size() >= m_resolved_paramstr_storage.size())
				{
					m_resolved_paramstr_storage.resize(tcomm.size() + 1);
				}

				snprintf(&m_resolved_paramstr_storage[0],
						 m_resolved_paramstr_storage.size(),
						 "%s",
						 tcomm.c_str());
			}
		}
		break;
	case PT_UINT8:
		ASSERT(payload_len == sizeof(uint8_t));
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo8, PRId8, PRIX8);

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         prfmt, *(uint8_t *)payload);
		break;
	case PT_UINT16:
		ASSERT(payload_len == sizeof(uint16_t));
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo16, PRId16, PRIX16);

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         prfmt, *(uint16_t *)payload);
		break;
	case PT_UINT32:
		ASSERT(payload_len == sizeof(uint32_t));
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo32, PRId32, PRIX32);

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         prfmt, *(uint32_t *)payload);
		break;
	case PT_ERRNO:
	{
		ASSERT(payload_len == sizeof(int64_t));

		int64_t val = *(int64_t *)payload;

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%" PRId64, val);

		//
		// Resolve this as an errno
		//
		string errstr;

		if(val < 0)
		{
			errstr = sinsp_utils::errno_to_str((int32_t)val);

			if(errstr != "")
			{
				snprintf(&m_resolved_paramstr_storage[0],
				         m_resolved_paramstr_storage.size(),
				         "%s", errstr.c_str());
			}
		}
	}
	break;
	case PT_UINT64:
		ASSERT(payload_len == sizeof(uint64_t));
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo64, PRId64, PRIX64);

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         prfmt, *(int64_t *)payload);

		break;
	case PT_CHARBUF:
		//
		// Make sure the string will fit
		//
		if(payload_len > m_paramstr_storage.size())
		{
			m_paramstr_storage.resize(payload_len);
		}

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%s", payload);
		break;
	case PT_FSPATH:
	{
		strcpy_sanitized(&m_paramstr_storage[0],
			payload,
			MIN(payload_len, (uint32_t)m_paramstr_storage.size()));

		sinsp_threadinfo* tinfo = get_thread_info();

		if(tinfo && payload_len > 0)
		{
			if (strncmp(payload, "<NA>", 4) != 0)
			{
				string cwd = tinfo->get_cwd();

				if(payload_len + cwd.length() >= m_resolved_paramstr_storage.size())
				{
					m_resolved_paramstr_storage.resize(payload_len + cwd.length() + 1, 0);
				}

				if(!sinsp_utils::concatenate_paths(&m_resolved_paramstr_storage[0],
					(uint32_t)m_resolved_paramstr_storage.size(),
					(char*)cwd.c_str(),
					(uint32_t)cwd.length(),
					payload,
					payload_len))
				{
					m_resolved_paramstr_storage[0] = 0;
				}
			}
		}
		else
		{
			*resolved_str = &m_paramstr_storage[0];
		}
	}
	break;
	case PT_BYTEBUF:
	{
		/* This would include quotes around the output string
		            m_paramstr_storage[0] = '"';
		            cres = binary_buffer_to_string(m_paramstr_storage + 1,
		                param->m_val,
		                m_paramstr_storage.size() - 2,
		                param->m_len);

		            m_paramstr_storage[cres + 1] = '"';
		            m_paramstr_storage[cres + 2] = 0;
		*/
		while(true)
		{
			uint32_t blen = binary_buffer_to_string(&m_paramstr_storage[0],
				payload,
				(uint32_t)m_paramstr_storage.size() - 1,
				payload_len,
				fmt);

			if(blen >= m_paramstr_storage.size() - 1)
			{
				//
				// The buffer didn't fit, expand it and try again
				//
				m_paramstr_storage.resize(m_paramstr_storage.size() * 2);
				continue;
			}

			ASSERT(m_inspector != NULL);
			if(m_inspector->m_max_evt_output_len != 0 &&
				blen > m_inspector->m_max_evt_output_len &&
				fmt == PF_NORMAL)
			{
				uint32_t real_len = MIN(blen, m_inspector->m_max_evt_output_len);

				m_rawbuf_str_len = real_len;
				if(real_len > 3)
				{
					m_paramstr_storage[real_len - 3] = '.';
					m_paramstr_storage[real_len - 2] = '.';
					m_paramstr_storage[real_len - 1] = '.';
				}

				m_paramstr_storage[real_len] = 0;
			}
			else
			{
				m_rawbuf_str_len = blen;
			}
			break;
		}
	}
	break;
	case PT_SOCKADDR:
		if(payload_len == 0)
		{
			snprintf(&m_paramstr_storage[0],
			         m_paramstr_storage.size(),
			         "NULL");

			break;
		}
		else if(payload[0] == AF_UNIX)
		{
			ASSERT(payload_len > 1);

			//
			// Sanitize the file string.
			//
            string sanitized_str = payload + 1;
	    sanitize_string(sanitized_str);

			snprintf(&m_paramstr_storage[0],
				m_paramstr_storage.size(),
				"%s",
				sanitized_str.c_str());
		}
		else if(payload[0] == PPM_AF_INET)
		{
			if(payload_len == 1 + 4 + 2)
			{
				ipv4serverinfo addr;
				addr.m_ip = *(uint32_t*)(payload + 1);
				addr.m_port = *(uint16_t*)(payload+5);
				addr.m_l4proto = (m_fdinfo != NULL) ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN;
				string straddr = ipv4serveraddr_to_string(&addr, m_inspector->m_hostname_and_port_resolution_enabled);
				snprintf(&m_paramstr_storage[0],
					   	 m_paramstr_storage.size(),
					   	 "%s",
					   	 straddr.c_str());
			}
			else
			{
				ASSERT(false);
				snprintf(&m_paramstr_storage[0],
				         m_paramstr_storage.size(),
				         "INVALID IPv4");
			}
		}
		else if(payload[0] == PPM_AF_INET6)
		{
			if(payload_len == 1 + 16 + 2)
			{
				ipv6serverinfo addr;
				memcpy((uint8_t *) addr.m_ip.m_b, (uint8_t *) payload+1, sizeof(addr.m_ip.m_b));
				addr.m_port = *(uint16_t*)(payload+17);
				addr.m_l4proto = (m_fdinfo != NULL) ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN;
				string straddr = ipv6serveraddr_to_string(&addr, m_inspector->m_hostname_and_port_resolution_enabled);
				snprintf(&m_paramstr_storage[0],
					   	 m_paramstr_storage.size(),
					   	 "%s",
					   	 straddr.c_str());
			}
			else
			{
				ASSERT(false);
				snprintf(&m_paramstr_storage[0],
				         m_paramstr_storage.size(),
				         "INVALID IPv6");
			}
		}
		else
		{
			snprintf(&m_paramstr_storage[0],
			         m_paramstr_storage.size(),
			         "family %d", (int)payload[0]);
		}
		break;
	case PT_SOCKTUPLE:
 		if(payload_len == 0)
		{
			snprintf(&m_paramstr_storage[0],
			         m_paramstr_storage.size(),
			         "NULL");

			break;
		}

		if(payload[0] == PPM_AF_INET)
		{
			if(payload_len == 1 + 4 + 2 + 4 + 2)
			{
				ipv4tuple addr;
				addr.m_fields.m_sip = *(uint32_t*)(payload + 1);
				addr.m_fields.m_sport = *(uint16_t*)(payload+5);
				addr.m_fields.m_dip = *(uint32_t*)(payload + 7);
				addr.m_fields.m_dport = *(uint16_t*)(payload+11);
				addr.m_fields.m_l4proto = (m_fdinfo != NULL) ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN;
				string straddr = ipv4tuple_to_string(&addr, m_inspector->m_hostname_and_port_resolution_enabled);
				snprintf(&m_paramstr_storage[0],
					   	 m_paramstr_storage.size(),
					   	 "%s",
					   	 straddr.c_str());
			}
			else
			{
				ASSERT(false);
				snprintf(&m_paramstr_storage[0],
				         m_paramstr_storage.size(),
				         "INVALID IPv4");
			}
		}
		else if(payload[0] == PPM_AF_INET6)
		{
			if(payload_len == 1 + 16 + 2 + 16 + 2)
			{
				uint8_t* sip6 = (uint8_t*)payload + 1;
				uint8_t* dip6 = (uint8_t*)payload + 19;
				uint8_t* sip = (uint8_t*)payload + 13;
				uint8_t* dip = (uint8_t*)payload + 31;

				if(sinsp_utils::is_ipv4_mapped_ipv6(sip6) && sinsp_utils::is_ipv4_mapped_ipv6(dip6))
				{
					ipv4tuple addr;
					addr.m_fields.m_sip = *(uint32_t*)sip;
					addr.m_fields.m_sport = *(uint16_t*)(payload+17);
					addr.m_fields.m_dip = *(uint32_t*)dip;
					addr.m_fields.m_dport = *(uint16_t*)(payload+35);
					addr.m_fields.m_l4proto = (m_fdinfo != NULL) ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN;
					string straddr = ipv4tuple_to_string(&addr, m_inspector->m_hostname_and_port_resolution_enabled);

					snprintf(&m_paramstr_storage[0],
							 m_paramstr_storage.size(),
							 "%s",
							 straddr.c_str());
					break;
				}
				else
				{
					char srcstr[INET6_ADDRSTRLEN];
					char dststr[INET6_ADDRSTRLEN];
					if(inet_ntop(AF_INET6, sip6, srcstr, sizeof(srcstr)) &&
						inet_ntop(AF_INET6, dip6, dststr, sizeof(dststr)))
					{
						snprintf(&m_paramstr_storage[0],
								 m_paramstr_storage.size(),
								 "%s:%s->%s:%s",
								 srcstr,
								 port_to_string(*(uint16_t*)(payload + 17), (m_fdinfo != NULL) ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN, m_inspector->m_hostname_and_port_resolution_enabled).c_str(),
								 dststr,
								 port_to_string(*(uint16_t*)(payload + 35), (m_fdinfo != NULL) ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN, m_inspector->m_hostname_and_port_resolution_enabled).c_str());
						break;
					}
				}
			}

			ASSERT(false);
			snprintf(&m_paramstr_storage[0],
				        m_paramstr_storage.size(),
				        "INVALID IPv6");
		}
		else if(payload[0] == AF_UNIX)
		{
			ASSERT(payload_len > 17);

			//
			// Sanitize the file string.
			//
            string sanitized_str = payload + 17;
	    sanitize_string(sanitized_str);

			snprintf(&m_paramstr_storage[0],
				m_paramstr_storage.size(),
				"%" PRIx64 "->%" PRIx64 " %s",
				*(uint64_t*)(payload + 1),
				*(uint64_t*)(payload + 9),
				sanitized_str.c_str());
		}
		else
		{
			snprintf(&m_paramstr_storage[0],
			         m_paramstr_storage.size(),
			         "family %d", (int)payload[0]);
		}
		break;
	case PT_FDLIST:
		{
			sinsp_threadinfo* tinfo = get_thread_info();
			if(!tinfo)
			{
				break;
			}

			uint16_t nfds = *(uint16_t *)payload;
			uint32_t pos = 2;
			uint32_t spos = 0;

			m_paramstr_storage[0] = 0;

			for(j = 0; j < nfds; j++)
			{
				char tch;
				int64_t fd = *(int64_t *)(payload + pos);

				sinsp_fdinfo_t *fdinfo = tinfo->get_fd(fd);
				if(fdinfo)
				{
					tch = fdinfo->get_typechar();
				}
				else
				{
					tch = '?';
				}

				int r = snprintf(&m_paramstr_storage[0] + spos,
						m_paramstr_storage.size() - spos,
						"%" PRIu64 ":%c%x%c",
						fd,
						tch,
						(uint32_t) * (int16_t *)(payload + pos + 8),
						(j < (uint32_t)(nfds - 1)) ? ' ' : '\0');

				if(r < 0 || spos + r >= m_paramstr_storage.size() - 1)
				{
					m_paramstr_storage[m_paramstr_storage.size() - 1] = 0;
					break;
				}

				spos += r;
				pos += 10;
			}
		}
		break;
	case PT_SYSCALLID:
		{
			uint16_t scid  = *(uint16_t *)payload;
			if(scid >= PPM_SC_MAX)
			{
				ASSERT(false);
				snprintf(&m_paramstr_storage[0],
						 m_paramstr_storage.size(),
						 "<unknown syscall>");
				break;
			}

			const struct ppm_syscall_desc* desc = &(g_infotables.m_syscall_info_table[scid]);

			snprintf(&m_paramstr_storage[0],
				m_paramstr_storage.size(),
				"%" PRIu16,
				scid);

			snprintf(&m_resolved_paramstr_storage[0],
				m_resolved_paramstr_storage.size(),
				"%s",
				desc->name);
		}
		break;
	case PT_SIGTYPE:
		{
			const char* sigstr;

			ASSERT(payload_len == sizeof(uint8_t));
			uint8_t val = *(uint8_t *)payload;

			sigstr = sinsp_utils::signal_to_str(val);

			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%" PRIu8, val);

			if(sigstr)
			{
				snprintf(&m_resolved_paramstr_storage[0],
							m_resolved_paramstr_storage.size(),
							"%s", sigstr);
			}
		}
		break;
	case PT_RELTIME:
		{
			string sigstr;

			ASSERT(payload_len == sizeof(uint64_t));
			uint64_t val = *(uint64_t *)payload;

			if(val == (uint64_t)(-1))
			{
				snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "none");
				m_resolved_paramstr_storage[0] = '\0';
			}
			else
			{
				snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%" PRIu64, val);

				snprintf(&m_resolved_paramstr_storage[0],
					 m_resolved_paramstr_storage.size(),
					 "%lgs",
					 ((double)val) / 1000000000);
			}
		}
		break;
	case PT_FLAGS8:
	case PT_FLAGS16:
	case PT_FLAGS32:
		{
			uint32_t val = (param_info->type == PT_FLAGS8) ? *(uint8_t *)payload :
				(param_info->type == PT_FLAGS16) ? *(uint16_t *)payload : *(uint32_t *)payload;
			snprintf(&m_paramstr_storage[0],
				     m_paramstr_storage.size(),
				     "%" PRIu32, val);

			const struct ppm_name_value *flags = (const struct ppm_name_value *)m_info->params[id].info;
			const char *separator = "";
			uint32_t initial_val = val;
			uint32_t j = 0;

			while(flags != NULL && flags->name != NULL && flags->value != initial_val)
			{
				// If flag is 0, then initial_val needs to be 0 for the flag to be resolved
				if((flags->value == 0 && initial_val == 0) ||
				   (flags->value != 0 && (val & flags->value) == flags->value && val != 0))
				{
					if(m_resolved_paramstr_storage.size() < j + strlen(separator) + strlen(flags->name))
					{
						m_resolved_paramstr_storage.resize(m_resolved_paramstr_storage.size() * 2);
					}

					j += snprintf(&m_resolved_paramstr_storage[j],
								  m_resolved_paramstr_storage.size(),
							 	  "%s%s",
							 	  separator,
							 	  flags->name);

					separator = "|";
					// We remove current flags value to avoid duplicate flags e.g. PPM_O_RDWR, PPM_O_RDONLY, PPM_O_WRONLY
					val &= ~flags->value;
				}

				flags++;
			}

			if(flags != NULL && flags->name != NULL)
			{
				j += snprintf(&m_resolved_paramstr_storage[j],
							  m_resolved_paramstr_storage.size(),
							  "%s%s",
							  separator,
							  flags->name);
			}

			break;
		}
	case PT_MODE:
		{
			uint32_t val = *(uint32_t *)payload;
			SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo32, PRId32, PRIX32);
			snprintf(&m_paramstr_storage[0],
					m_paramstr_storage.size(),
					prfmt, val);

			const struct ppm_name_value *mode = (const struct ppm_name_value *)m_info->params[id].info;
			const char *separator = "";
			uint32_t initial_val = val;
			uint32_t j = 0;

			while(mode != NULL && mode->name != NULL && mode->value != initial_val)
			{
				// If mode is 0, then initial_val needs to be 0 for the mode to be resolved
				if((mode->value == 0 && initial_val == 0) ||
				   (mode->value != 0 && (val & mode->value) == mode->value && val != 0))
				{
					size_t params_len = j + strlen(separator) + strlen(mode->name);
					if(m_resolved_paramstr_storage.size() < params_len)
					{
						m_resolved_paramstr_storage.resize(params_len + 1);
					}

					j += snprintf(&m_resolved_paramstr_storage[j],
								m_resolved_paramstr_storage.size(),
								"%s%s",
								separator,
								mode->name);

					separator = "|";
					// We remove current mode value to avoid duplicates
					val &= ~mode->value;
				}

				mode++;
			}

			if(mode != NULL && mode->name != NULL)
			{
				j += snprintf(&m_resolved_paramstr_storage[j],
							  m_resolved_paramstr_storage.size(),
							  "%s%s",
							  separator,
							  mode->name);
			}

			break;
		}
	case PT_ABSTIME:
		//
		// XXX not implemented yet
		//
		ASSERT(false);
	case PT_DYN:
		ASSERT(false);
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "INVALID DYNAMIC PARAMETER");
		break;
	case PT_UID:
	{
		uint32_t val = *(uint32_t *)payload;
		if (val < std::numeric_limits<uint32_t>::max())
		{
			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%d", val);
			auto find_it = m_inspector->get_userlist()->find(val);
			if (find_it != m_inspector->get_userlist()->end())
			{
				scap_userinfo* user_info = find_it->second;
				strcpy_sanitized(&m_resolved_paramstr_storage[0], user_info->name,
								(uint32_t)m_resolved_paramstr_storage.size());
			}
			else
			{
				snprintf(&m_resolved_paramstr_storage[0],
						m_resolved_paramstr_storage.size(),
						"<NA>");
			}
		}
		else
		{
			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "-1");
			snprintf(&m_resolved_paramstr_storage[0],
					m_resolved_paramstr_storage.size(),
					"<NONE>");
		}
		break;
	}
	case PT_GID:
	{
		uint32_t val = *(uint32_t *)payload;
		if (val < std::numeric_limits<uint32_t>::max())
		{
			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%d", val);
			auto find_it = m_inspector->get_grouplist()->find(val);
			if (find_it != m_inspector->get_grouplist()->end())
			{
				scap_groupinfo* group_info = find_it->second;
				strcpy_sanitized(&m_resolved_paramstr_storage[0], group_info->name,
								(uint32_t)m_resolved_paramstr_storage.size());
			}
			else
			{
				snprintf(&m_resolved_paramstr_storage[0],
						m_resolved_paramstr_storage.size(),
						"<NA>");
			}
		}
		else
		{
			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "-1");
			snprintf(&m_resolved_paramstr_storage[0],
					m_resolved_paramstr_storage.size(),
					"<NONE>");
		}
		break;
	}
	case PT_CHARBUFARRAY:
	{
		ASSERT(param->m_len == sizeof(uint64_t));
		vector<char*>* strvect = (vector<char*>*)*(uint64_t *)param->m_val;

		m_paramstr_storage[0] = 0;

		while(true)
		{
			vector<char*>::iterator it;
			vector<char*>::iterator itbeg;
			bool need_to_resize = false;

			//
			// Copy the arguments
			//
			char* dst = &m_paramstr_storage[0];
			char* dstend = &m_paramstr_storage[0] + m_paramstr_storage.size() - 2;

			for(it = itbeg = strvect->begin(); it != strvect->end(); ++it)
			{
				char* src = *it;

				if(it != itbeg)
				{
					if(dst < dstend - 1)
					{
						*dst++ = '.';
					}
				}

				while(*src != 0 && dst < dstend)
				{
					*dst++ = *src++;
				}

				if(dst == dstend)
				{
					//
					// Reached the end of m_paramstr_storage, we need to resize it
					//
					need_to_resize = true;
					break;
				}
			}

			if(need_to_resize)
			{
				m_paramstr_storage.resize(m_paramstr_storage.size() * 2);
				continue;
			}

			*dst = 0;

			break;
		}
	}
	break;
	case PT_CHARBUF_PAIR_ARRAY:
	{
		ASSERT(param->m_len == sizeof(uint64_t));
		pair<vector<char*>*, vector<char*>*>* pairs =
			(pair<vector<char*>*, vector<char*>*>*)*(uint64_t *)param->m_val;

		m_paramstr_storage[0] = 0;

		if(pairs->first->size() != pairs->second->size())
		{
			ASSERT(false);
			break;
		}

		while(true)
		{
			vector<char*>::iterator it1;
			vector<char*>::iterator itbeg1;
			vector<char*>::iterator it2;
			vector<char*>::iterator itbeg2;
			bool need_to_resize = false;

			//
			// Copy the arguments
			//
			char* dst = &m_paramstr_storage[0];
			char* dstend = &m_paramstr_storage[0] + m_paramstr_storage.size() - 2;

			for(it1 = itbeg1 = pairs->first->begin(), it2 = itbeg2 = pairs->second->begin();
			it1 != pairs->first->end();
				++it1, ++it2)
			{
				char* src = *it1;

				if(it1 != itbeg1)
				{
					if(dst < dstend - 1)
					{
						*dst++ = ',';
					}
				}

				//
				// Copy the first string
				//
				while(*src != 0 && dst < dstend)
				{
					*dst++ = *src++;
				}

				if(dst < dstend - 1)
				{
					*dst++ = ':';
				}

				//
				// Copy the second string
				//
				src = *it2;
				while(*src != 0 && dst < dstend)
				{
					*dst++ = *src++;
				}

				if(dst == dstend)
				{
					//
					// Reached the end of m_paramstr_storage, we need to resize it
					//
					need_to_resize = true;
					break;
				}
			}

			if(need_to_resize)
			{
				m_paramstr_storage.resize(m_paramstr_storage.size() * 2);
				continue;
			}

			*dst = 0;

			break;
		}

		break;
	}
	case PT_SIGSET:
	{
		ASSERT(payload_len == sizeof(uint32_t));
		uint32_t val = *(uint32_t *)payload;

		m_resolved_paramstr_storage[0] = '\0';
		m_paramstr_storage[0]          = '\0';

		char* storage = &m_paramstr_storage[0];
		int remaining = (int)m_paramstr_storage.size();
		bool first = true;

		for(int sig = 0; sig < 32; sig++)
		{
			if(val & (1U << sig) )
			{
				const char* sigstr = sinsp_utils::signal_to_str(sig+1);
				if(sigstr)
				{
					int printed = snprintf(storage, remaining,
							       "%s%s",
							       !first ? " " : "",
							       sigstr);
					if(printed >= remaining)
					{
						storage[remaining-1] = '\0';
						break;
					}

					first	   = false;
					storage	  += printed;
					remaining -= printed;
				}
			}
		}
		break;
	}
	default:
		ASSERT(false);
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "(n.a.)");
		break;
	}

	*resolved_str = &m_resolved_paramstr_storage[0];

	return &m_paramstr_storage[0];
}

string sinsp_evt::get_param_value_str(const string &name, bool resolved)
{
	for(uint32_t i = 0; i < get_num_params(); i++)
	{
		if(name == get_param_name(i))
		{
			return get_param_value_str(i, resolved);
		}
	}

	return string("");
}

string sinsp_evt::get_param_value_str(const char *name, bool resolved)
{
	// TODO fix this !!
	string s_name = string(name);
	return get_param_value_str(s_name, resolved);
}

string sinsp_evt::get_param_value_str(uint32_t i, bool resolved)
{
	const char *param_value_str;
	const char *val_str;
	val_str = get_param_as_str(i, &param_value_str);

	if(resolved)
	{
		return string((*param_value_str == '\0')? val_str : param_value_str);
	}
	else
	{
		return string(val_str);
	}
}

const char* sinsp_evt::get_param_value_str(const char* name, OUT const char** resolved_str, param_fmt fmt)
{
	for(uint32_t i = 0; i < get_num_params(); i++)
	{
		if(strcmp(name, get_param_name(i)) == 0)
		{
			return get_param_as_str(i, resolved_str, fmt);
		}
	}

	*resolved_str = NULL;
	return NULL;
}

const sinsp_evt_param* sinsp_evt::get_param_value_raw(const char* name)
{
	//
	// Make sure the params are actually loaded
	//
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	//
	// Locate the parameter given the name
	//
	uint32_t np = get_num_params();

	for(uint32_t j = 0; j < np; j++)
	{
		if(strcmp(name, get_param_name(j)) == 0)
		{
			return &(m_params[j]);
		}
	}

	return NULL;
}

void sinsp_evt::get_category(OUT sinsp_evt::category* cat)
{
	if(m_pevt->type == PPME_GENERIC_E ||
		m_pevt->type == PPME_GENERIC_X)
	{
		//
		// This event is a syscall that doesn't have a filler yet.
		// The category can be found in g_syscall_info_table.
		//
		sinsp_evt_param *parinfo = get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint16_t));
		uint16_t id = *(uint16_t *)parinfo->m_val;

		if(id < PPM_SC_MAX)
		{
			cat->m_category = g_infotables.m_syscall_info_table[id].category;
			cat->m_subcategory = sinsp_evt::SC_NONE;
		}
		else
		{
			ASSERT(false);
		}
	}
	else
	{
		//
		// This event has a real filler.
		// The category can be found in the info struct.
		//
		cat->m_category = m_info->category;

		//
		// For EC_IO and EC_WAIT events, we dig into the fd state to get the category
		// and fdtype
		//
		if(cat->m_category & EC_IO_BASE)
		{
			if(!m_fdinfo)
			{
				//
				// The fd info is not present, likely because we missed its creation.
				//
				cat->m_subcategory = SC_UNKNOWN;
				return;
			}
			else
			{
				switch(m_fdinfo->m_type)
				{
					case SCAP_FD_FILE:
					case SCAP_FD_FILE_V2:
					case SCAP_FD_DIRECTORY:
						cat->m_subcategory = SC_FILE;
						break;
					case SCAP_FD_IPV4_SOCK:
					case SCAP_FD_IPV6_SOCK:
						cat->m_subcategory = SC_NET;
						break;
					case SCAP_FD_IPV4_SERVSOCK:
					case SCAP_FD_IPV6_SERVSOCK:
						cat->m_subcategory = SC_NET;
						break;
					case SCAP_FD_FIFO:
					case SCAP_FD_UNIX_SOCK:
					case SCAP_FD_EVENT:
					case SCAP_FD_SIGNALFD:
					case SCAP_FD_INOTIFY:
						cat->m_subcategory = SC_IPC;
						break;
					case SCAP_FD_UNSUPPORTED:
					case SCAP_FD_EVENTPOLL:
					case SCAP_FD_TIMERFD:
					case SCAP_FD_NETLINK:
						cat->m_subcategory = SC_OTHER;
						break;
					case SCAP_FD_UNKNOWN:
						cat->m_subcategory = SC_OTHER;
						break;
					default:
//						ASSERT(false);
						cat->m_subcategory = SC_UNKNOWN;
						break;
				}
			}
		}
		else
		{
			cat->m_subcategory = sinsp_evt::SC_NONE;
		}
	}
}

bool sinsp_evt::is_filtered_out()
{
	return m_filtered_out;
}

#ifdef HAS_FILTERING
scap_dump_flags sinsp_evt::get_dump_flags(OUT bool* should_drop)
{
	uint32_t dflags = SCAP_DF_NONE;
	*should_drop = false;

	if(m_filtered_out)
	{
		if(m_inspector->m_isfatfile_enabled)
		{
			ppm_event_flags eflags = get_info_flags();

			if(eflags & EF_MODIFIES_STATE)
			{
				dflags = SCAP_DF_STATE_ONLY;
			}
			else
			{
				*should_drop = true;
			}
		}
		else
		{
			*should_drop = true;
		}

		if(*should_drop)
		{
			ppm_event_category ecat = get_info_category();
			if(ecat & EC_INTERNAL)
			{
				*should_drop = false;
			}
		}
	}

	if(m_flags & sinsp_evt::SINSP_EF_IS_TRACER)
	{
		dflags |= SCAP_DF_TRACER;
	}

	return (scap_dump_flags)dflags;
}
#endif

bool sinsp_evt::simple_consumer_consider()
{
	uint16_t etype = get_type();

	if(etype == PPME_GENERIC_E || etype == PPME_GENERIC_X)
	{
		sinsp_evt_param *parinfo = get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint16_t));
		uint16_t scid = *(uint16_t *)parinfo->m_val;

		return sinsp::simple_consumer_consider_syscallid(scid);
	}

	return sinsp::simple_consumer_consider_evtnum(etype);
}

bool sinsp_evt::is_syscall_error() const
{
	return (m_errorcode != 0) &&
	       (m_errorcode != SE_EINPROGRESS) &&
	       (m_errorcode != SE_EAGAIN) &&
	       (m_errorcode != SE_ETIMEDOUT);
}

bool sinsp_evt::is_file_open_error() const
{
	return (m_fdinfo == nullptr) &&
	       ((m_pevt->type == PPME_SYSCALL_OPEN_X) ||
		(m_pevt->type == PPME_SYSCALL_CREAT_X) ||
		(m_pevt->type == PPME_SYSCALL_OPENAT_X) ||
		(m_pevt->type == PPME_SYSCALL_OPENAT_2_X));
}

bool sinsp_evt::is_file_error() const
{
	return is_file_open_error() ||
	       ((m_fdinfo != nullptr) &&
		((m_fdinfo->m_type == SCAP_FD_FILE) ||
		 (m_fdinfo->m_type == SCAP_FD_FILE_V2)));
}

bool sinsp_evt::is_network_error() const
{
	if(m_fdinfo != nullptr)
	{
		return (m_fdinfo->m_type == SCAP_FD_IPV4_SOCK) ||
		       (m_fdinfo->m_type == SCAP_FD_IPV6_SOCK);
	}
	else
	{
		return (m_pevt->type == PPME_SOCKET_ACCEPT_X) ||
		       (m_pevt->type == PPME_SOCKET_ACCEPT4_X) ||
		       (m_pevt->type == PPME_SOCKET_ACCEPT_5_X) ||
		       (m_pevt->type == PPME_SOCKET_ACCEPT4_5_X) ||
		       (m_pevt->type == PPME_SOCKET_CONNECT_X) ||
		       (m_pevt->type == PPME_SOCKET_BIND_X);
	}
}
