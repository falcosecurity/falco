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

#include <stdio.h>
#include <stdlib.h>

#include "scap.h"
#include "scap-int.h"
#include "scap_savefile.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include "uthash.h"
#ifdef _WIN32
#include <Ws2tcpip.h>
#elif defined(__APPLE__)
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#else
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <unistd.h>
#include <sys/param.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <errno.h>
#include <netinet/tcp.h>
#if defined(__linux__)
#if HAVE_SYS_MKDEV_H
#include <sys/mkdev.h>
#endif
#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
//#include <linux/sock_diag.h>
//#include <linux/unix_diag.h>
#endif
#endif

#define SOCKET_SCAN_BUFFER_SIZE 1024 * 1024

int32_t scap_fd_print_ipv6_socket_info(scap_t *handle, scap_fdinfo *fdi, OUT char *str, uint32_t stlen)
{
	char source_address[100];
	char destination_address[100];
	if(NULL == inet_ntop(AF_INET6,fdi->info.ipv6info.sip,source_address,100))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE,
			 "Could not convert IPv6 source address 0x%x%x%x%x (%s)",
			 fdi->info.ipv6info.sip[0],
			 fdi->info.ipv6info.sip[1],
			 fdi->info.ipv6info.sip[2],
			 fdi->info.ipv6info.sip[3],
			 scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}
	if(NULL == inet_ntop(AF_INET6,fdi->info.ipv6info.dip,destination_address,100))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE,
			 "Could not convert IPv6 source address 0x%x%x%x%x (%s)",
			 fdi->info.ipv6info.dip[0],
			 fdi->info.ipv6info.dip[1],
			 fdi->info.ipv6info.dip[2],
			 fdi->info.ipv6info.dip[3],
			 scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}
	snprintf(str,stlen,"%s:%u->%s:%u",source_address,fdi->info.ipv6info.sport,destination_address,fdi->info.ipv6info.dport);
	return SCAP_SUCCESS;
}

int32_t scap_fd_print_ipv6_server_socket_info(scap_t *handle, scap_fdinfo *fdi, OUT char *str, uint32_t stlen)
{
	char address[100];
	if(NULL == inet_ntop(AF_INET6,fdi->info.ipv6serverinfo.ip,address,100))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE,
			 "Could not convert IPv6 source address 0x%x%x%x%x (%s)",
			 fdi->info.ipv6serverinfo.ip[0],
			 fdi->info.ipv6serverinfo.ip[1],
			 fdi->info.ipv6serverinfo.ip[2],
			 fdi->info.ipv6serverinfo.ip[3],
			 scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}
	snprintf(str,stlen,"%s:%u->:::*",address,fdi->info.ipv6serverinfo.port);
	return SCAP_SUCCESS;
}

//
// Convert an fd entry's info into a string
//
int32_t scap_fd_info_to_string(scap_t *handle, scap_fdinfo *fdi, OUT char *str, uint32_t stlen)
{
	//
	// Input validation
	//
	if((fdi)->type == SCAP_FD_UNKNOWN)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "fd type unknown");
		return SCAP_FAILURE;
	}

	switch(fdi->type)
	{
	case SCAP_FD_IPV4_SOCK:
		snprintf(str, stlen, "%u.%u.%u.%u:%u->%u.%u.%u.%u:%u",
		         fdi->info.ipv4info.sip >> 24,
		         fdi->info.ipv4info.sip >> 16 & 0xff,
		         fdi->info.ipv4info.sip >> 8 & 0xff,
		         fdi->info.ipv4info.sip & 0xff,
		         (uint32_t)fdi->info.ipv4info.sport,
		         fdi->info.ipv4info.dip >> 24,
		         fdi->info.ipv4info.dip >> 16 & 0xff,
		         fdi->info.ipv4info.dip >> 8 & 0xff,
		         fdi->info.ipv4info.dip & 0xff,
		         (uint32_t)fdi->info.ipv4info.dport);
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		snprintf(str, stlen, "%u.%u.%u.%u:%u",
		         fdi->info.ipv4serverinfo.ip >> 24,
		         fdi->info.ipv4serverinfo.ip >> 16 & 0xff,
		         fdi->info.ipv4serverinfo.ip >> 8 & 0xff,
		         fdi->info.ipv4serverinfo.ip & 0xff,
		         (uint32_t)fdi->info.ipv4serverinfo.port);
		break;
	case SCAP_FD_IPV6_SOCK:
		return scap_fd_print_ipv6_socket_info(handle,fdi,str,stlen);
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		return scap_fd_print_ipv6_server_socket_info(handle,fdi,str,stlen);
		break;
	case SCAP_FD_FIFO:
		snprintf(str, stlen, "<PIPE>");
		break;
	case SCAP_FD_SIGNALFD:
		snprintf(str, stlen, "<SIGNAL>");
		break;
	case SCAP_FD_EVENTPOLL:
		snprintf(str, stlen, "<POLL>");
		break;
	case SCAP_FD_TIMERFD:
		snprintf(str, stlen, "<TIMER>");
		break;
	case SCAP_FD_EVENT:
		snprintf(str, stlen, "<EVENT>");
		break;
	case SCAP_FD_INOTIFY:
		snprintf(str, stlen, "<INOTIFY>");
		break;
	case SCAP_FD_UNIX_SOCK:
		snprintf(str, stlen, "%"PRIi64" %"PRIu64" %"PRIX64"-> %"PRIX64" %s", fdi->fd,fdi->ino, fdi->info.unix_socket_info.source,fdi->info.unix_socket_info.destination, fdi->info.unix_socket_info.fname);
		break;
	case SCAP_FD_FILE_V2:
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
		break;
 	case SCAP_FD_UNSUPPORTED:
 		snprintf(str, stlen, "<UNSUPPORTED>");
 		break;
 	case SCAP_FD_NETLINK:
 		snprintf(str, stlen, "<NETLINK>");
 		break;
	default:
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "fd type unrecognized");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Calculate the length on disk of an fd entry's info
//
uint32_t scap_fd_info_len(scap_fdinfo *fdi)
{
	//
	// NB: new fields must be appended
	//

	uint32_t res = sizeof(uint32_t) + sizeof(fdi->ino) + 1 + sizeof(fdi->fd);

	switch(fdi->type)
	{
	case SCAP_FD_IPV4_SOCK:
		res +=  4 +     // sip
		        4 +     // dip
		        2 +     // sport
		        2 +     // dport
		        1;      // l4proto
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		res +=  4 +     // ip
		        2 +     // port
		        1;      // l4proto
		break;
	case SCAP_FD_IPV6_SOCK:
		res += 	sizeof(uint32_t) * 4 + // sip
				sizeof(uint32_t) * 4 + // dip
				sizeof(uint16_t) + // sport
				sizeof(uint16_t) + // dport
				sizeof(uint8_t); // l4proto
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		res += 	sizeof(uint32_t) * 4 + // ip
				sizeof(uint16_t) + // port
				sizeof(uint8_t); // l4proto
		break;
	case SCAP_FD_UNIX_SOCK:
		res +=
			sizeof(uint64_t) + // unix source
			sizeof(uint64_t) +  // unix destination
			(uint32_t)strnlen(fdi->info.unix_socket_info.fname, SCAP_MAX_PATH_SIZE) + 2;
		break;
	case SCAP_FD_FILE_V2:
		res += sizeof(uint32_t) + // open_flags
			(uint32_t)strnlen(fdi->info.regularinfo.fname, SCAP_MAX_PATH_SIZE) + 2 +
			sizeof(uint32_t); // dev
		break;
	case SCAP_FD_FIFO:
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
	case SCAP_FD_UNSUPPORTED:
	case SCAP_FD_EVENT:
	case SCAP_FD_SIGNALFD:
	case SCAP_FD_EVENTPOLL:
	case SCAP_FD_INOTIFY:
	case SCAP_FD_TIMERFD:
	case SCAP_FD_NETLINK:
		res += (uint32_t)strnlen(fdi->info.fname, SCAP_MAX_PATH_SIZE) + 2;    // 2 is the length field before the string
		break;
	default:
		ASSERT(false);
		break;
	}

	return res;
}

int scap_dump_write(scap_dumper_t *d, void* buf, unsigned len);

//
// Write the given fd info to disk
//
int32_t scap_fd_write_to_disk(scap_t *handle, scap_fdinfo *fdi, scap_dumper_t *d, uint32_t len)
{

	uint8_t type = (uint8_t)fdi->type;
	uint16_t stlen;
	if(scap_dump_write(d, &(len), sizeof(uint32_t)) != sizeof(uint32_t) ||
	        scap_dump_write(d, &(fdi->fd), sizeof(uint64_t)) != sizeof(uint64_t) ||
	        scap_dump_write(d, &(fdi->ino), sizeof(uint64_t)) != sizeof(uint64_t) ||
	        scap_dump_write(d, &(type), sizeof(uint8_t)) != sizeof(uint8_t))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi1)");
		return SCAP_FAILURE;
	}

	switch(fdi->type)
	{
	case SCAP_FD_IPV4_SOCK:
		if(scap_dump_write(d, &(fdi->info.ipv4info.sip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        scap_dump_write(d, &(fdi->info.ipv4info.dip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        scap_dump_write(d, &(fdi->info.ipv4info.sport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        scap_dump_write(d, &(fdi->info.ipv4info.dport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        scap_dump_write(d, &(fdi->info.ipv4info.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi2)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		if(scap_dump_write(d, &(fdi->info.ipv4serverinfo.ip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        scap_dump_write(d, &(fdi->info.ipv4serverinfo.port), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        scap_dump_write(d, &(fdi->info.ipv4serverinfo.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi3)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_IPV6_SOCK:
		if(scap_dump_write(d, (char*)fdi->info.ipv6info.sip, sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		        scap_dump_write(d, (char*)fdi->info.ipv6info.dip, sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		        scap_dump_write(d, &(fdi->info.ipv6info.sport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        scap_dump_write(d, &(fdi->info.ipv6info.dport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        scap_dump_write(d, &(fdi->info.ipv6info.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi7)");
		}
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		if(scap_dump_write(d, &(fdi->info.ipv6serverinfo.ip), sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		        scap_dump_write(d, &(fdi->info.ipv6serverinfo.port), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        scap_dump_write(d, &(fdi->info.ipv6serverinfo.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi8)");
		}
		break;
	case SCAP_FD_UNIX_SOCK:
		if(scap_dump_write(d, &(fdi->info.unix_socket_info.source), sizeof(uint64_t)) != sizeof(uint64_t) ||
		        scap_dump_write(d, &(fdi->info.unix_socket_info.destination), sizeof(uint64_t)) != sizeof(uint64_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi4)");
			return SCAP_FAILURE;
		}
		stlen = (uint16_t)strnlen(fdi->info.unix_socket_info.fname, SCAP_MAX_PATH_SIZE);
		if(scap_dump_write(d, &stlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		        (stlen > 0 && scap_dump_write(d, fdi->info.unix_socket_info.fname, stlen) != stlen))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi5)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_FILE_V2:
		if(scap_dump_write(d, &(fdi->info.regularinfo.open_flags), sizeof(uint32_t)) != sizeof(uint32_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi1)");
			return SCAP_FAILURE;
		}
		stlen = (uint16_t)strnlen(fdi->info.regularinfo.fname, SCAP_MAX_PATH_SIZE);
		if(scap_dump_write(d, &stlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
			(stlen > 0 && scap_dump_write(d, fdi->info.regularinfo.fname, stlen) != stlen))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi1)");
			return SCAP_FAILURE;
		}
		if(scap_dump_write(d, &(fdi->info.regularinfo.dev), sizeof(uint32_t)) != sizeof(uint32_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (dev)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_FIFO:
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
	case SCAP_FD_UNSUPPORTED:
	case SCAP_FD_EVENT:
	case SCAP_FD_SIGNALFD:
	case SCAP_FD_EVENTPOLL:
	case SCAP_FD_INOTIFY:
	case SCAP_FD_TIMERFD:
	case SCAP_FD_NETLINK:
		stlen = (uint16_t)strnlen(fdi->info.fname, SCAP_MAX_PATH_SIZE);
		if(scap_dump_write(d, &stlen,  sizeof(uint16_t)) != sizeof(uint16_t) ||
		        (stlen > 0 && scap_dump_write(d, fdi->info.fname, stlen) != stlen))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi6)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_UNKNOWN:
		// Ignore UNKNOWN fds without failing
		ASSERT(false);
		break;
	default:
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Unknown fdi type %d", fdi->type);
		ASSERT(false);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

uint32_t scap_fd_read_prop_from_disk(scap_t *handle, OUT void *target, size_t expected_size, OUT size_t *nbytes, gzFile f)
{
	size_t readsize;
	readsize = gzread(f, target, (unsigned int)expected_size);
	CHECK_READ_SIZE(readsize, expected_size);
	(*nbytes) += readsize;
	return SCAP_SUCCESS;
}

uint32_t scap_fd_read_fname_from_disk(scap_t* handle, char* fname,OUT size_t* nbytes, gzFile f)
{
	size_t readsize;
	uint16_t stlen;

	readsize = gzread(f, &(stlen), sizeof(uint16_t));
	CHECK_READ_SIZE(readsize, sizeof(uint16_t));

	if(stlen >= SCAP_MAX_PATH_SIZE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid filename len %"PRId32, stlen);
		return SCAP_FAILURE;
	}

	(*nbytes) += readsize;

	readsize = gzread(f, fname, stlen);
	CHECK_READ_SIZE(readsize, stlen);

	(*nbytes) += stlen;

	// NULL-terminate the string
	fname[stlen] = 0;
	return SCAP_SUCCESS;
}

//
// Populate the given fd by reading the info from disk
// Returns the number of read bytes.
//
uint32_t scap_fd_read_from_disk(scap_t *handle, OUT scap_fdinfo *fdi, OUT size_t *nbytes, uint32_t block_type, gzFile f)
{
	uint8_t type;
	uint32_t toread;
	int fseekres;
	uint32_t sub_len = 0;
	uint32_t res = SCAP_SUCCESS;
	*nbytes = 0;

	if((block_type == FDL_BLOCK_TYPE_V2 && scap_fd_read_prop_from_disk(handle, &sub_len, sizeof(uint32_t), nbytes, f)) ||
	        scap_fd_read_prop_from_disk(handle, &(fdi->fd), sizeof(fdi->fd), nbytes, f) ||
	        scap_fd_read_prop_from_disk(handle, &(fdi->ino), sizeof(fdi->ino), nbytes, f) ||
	        scap_fd_read_prop_from_disk(handle, &type, sizeof(uint8_t), nbytes, f))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not read prop block for fd");
		return SCAP_FAILURE;
	}

	// If new parameters are added, sub_len can be used to
	// see if they are available in the current capture.
	// For example, for a 32bit parameter:
	//
	// if(sub_len && (*nbytes + sizeof(uint32_t)) <= sub_len)
	// {
	//    ...
	// }

	fdi->type = (scap_fd_type)type;

	switch(fdi->type)
	{
	case SCAP_FD_IPV4_SOCK:
		if(gzread(f, &(fdi->info.ipv4info.sip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        gzread(f, &(fdi->info.ipv4info.dip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        gzread(f, &(fdi->info.ipv4info.sport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzread(f, &(fdi->info.ipv4info.dport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzread(f, &(fdi->info.ipv4info.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading the fd info from file (1)");
			return SCAP_FAILURE;
		}

		(*nbytes) += (sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint8_t));

		break;
	case SCAP_FD_IPV4_SERVSOCK:
		if(gzread(f, &(fdi->info.ipv4serverinfo.ip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        gzread(f, &(fdi->info.ipv4serverinfo.port), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzread(f, &(fdi->info.ipv4serverinfo.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading the fd info from file (2)");
			return SCAP_FAILURE;
		}

		(*nbytes) += (sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t));
		break;
	case SCAP_FD_IPV6_SOCK:
		if(gzread(f, (char*)fdi->info.ipv6info.sip, sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		        gzread(f, (char*)fdi->info.ipv6info.dip, sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		        gzread(f, &(fdi->info.ipv6info.sport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzread(f, &(fdi->info.ipv6info.dport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzread(f, &(fdi->info.ipv6info.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi3)");
		}
		(*nbytes) += (sizeof(uint32_t) * 4 + // sip
				sizeof(uint32_t) * 4 + // dip
				sizeof(uint16_t) + // sport
				sizeof(uint16_t) + // dport
				sizeof(uint8_t)); // l4proto
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		if(gzread(f, (char*)fdi->info.ipv6serverinfo.ip, sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4||
		        gzread(f, &(fdi->info.ipv6serverinfo.port), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzread(f, &(fdi->info.ipv6serverinfo.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi4)");
		}
		(*nbytes) += (sizeof(uint32_t) * 4 + // ip
				sizeof(uint16_t) + // port
				sizeof(uint8_t)); // l4proto
		break;
	case SCAP_FD_UNIX_SOCK:
		if(gzread(f, &(fdi->info.unix_socket_info.source), sizeof(uint64_t)) != sizeof(uint64_t) ||
		        gzread(f, &(fdi->info.unix_socket_info.destination), sizeof(uint64_t)) != sizeof(uint64_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading the fd info from file (fi5)");
			return SCAP_FAILURE;
		}

		(*nbytes) += (sizeof(uint64_t) + sizeof(uint64_t));
		res = scap_fd_read_fname_from_disk(handle, fdi->info.unix_socket_info.fname, nbytes, f);
		break;
	case SCAP_FD_FILE_V2:
		if(gzread(f, &(fdi->info.regularinfo.open_flags), sizeof(uint32_t)) != sizeof(uint32_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading the fd info from file (fi1)");
			return SCAP_FAILURE;
		}

		(*nbytes) += sizeof(uint32_t);
		res = scap_fd_read_fname_from_disk(handle, fdi->info.regularinfo.fname, nbytes, f);
		if (!sub_len || (sub_len < *nbytes + sizeof(uint32_t)))
		{
			break;
		}
		if(gzread(f, &(fdi->info.regularinfo.dev), sizeof(uint32_t)) != sizeof(uint32_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading the fd info from file (dev)");
			return SCAP_FAILURE;
		}
		(*nbytes) += sizeof(uint32_t);
		break;
	case SCAP_FD_FIFO:
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
	case SCAP_FD_UNSUPPORTED:
	case SCAP_FD_EVENT:
	case SCAP_FD_SIGNALFD:
	case SCAP_FD_EVENTPOLL:
	case SCAP_FD_INOTIFY:
	case SCAP_FD_TIMERFD:
	case SCAP_FD_NETLINK:
		res = scap_fd_read_fname_from_disk(handle, fdi->info.fname,nbytes,f);
		break;
	case SCAP_FD_UNKNOWN:
		ASSERT(false);
		break;
	default:
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading the fd info from file, wrong fd type %u", (uint32_t)fdi->type);
		return SCAP_FAILURE;
	}

	if(sub_len && *nbytes != sub_len)
	{
		if(*nbytes > sub_len)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted input file. Had read %zu bytes, but fdlist entry have length %u.",
				 *nbytes, sub_len);
			return SCAP_FAILURE;
		}
		toread = sub_len - *nbytes;
		fseekres = (int)gzseek(f, (long)toread, SEEK_CUR);
		if(fseekres == -1)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted input file. Can't skip %u bytes.",
				 (unsigned int)toread);
			return SCAP_FAILURE;
		}
		*nbytes = sub_len;
	}

	return res;
}

void scap_fd_free_ns_sockets_list(scap_t *handle, struct scap_ns_socket_list **sockets)
{
	struct scap_ns_socket_list *fdi;
	struct scap_ns_socket_list *tfdi;

	if(*sockets)
	{
		HASH_ITER(hh, *sockets, fdi, tfdi)
		{
			HASH_DEL(*sockets, fdi);
			scap_fd_free_table(handle, &fdi->sockets);
			free(fdi);
		}
		*sockets = NULL;
	}
}

void scap_fd_free_table(scap_t *handle, scap_fdinfo **fds)
{
	struct scap_fdinfo *fdi;
	struct scap_fdinfo *tfdi;

	if(*fds)
	{
		HASH_ITER(hh, *fds, fdi, tfdi)
		{
			HASH_DEL(*fds, fdi);
			free(fdi);
		}
		*fds = NULL;
	}
}

void scap_fd_free_proc_fd_table(scap_t *handle, scap_threadinfo *tinfo)
{
	if(tinfo->fdlist)
	{
		scap_fd_free_table(handle, &tinfo->fdlist);
	}
}


//
// remove an fd from a process table
//
void scap_fd_remove(scap_t *handle, scap_threadinfo *tinfo, int64_t fd)
{
	scap_fdinfo *fdi;

	//
	// Find the fd descriptor
	//
	HASH_FIND_INT64(tinfo->fdlist, &(fd), fdi);
	if(fdi == NULL)
	{
		//
		// Looks like there's no fd to remove.
		// Likely, the fd creation event was dropped.
		//
		//scap_proc_print_info(handle, tinfo);
		//      ASSERT(false);
		return;
	}

	HASH_DEL(tinfo->fdlist, fdi);
	free(fdi);
}

//
// Add the file descriptor info pointed by fdi to the fd table for process tinfo.
// Note: silently skips if fdi->type is SCAP_FD_UNKNOWN.
//
int32_t scap_add_fd_to_proc_table(scap_t *handle, scap_threadinfo *tinfo, scap_fdinfo *fdi, char *error)
{
	int32_t uth_status = SCAP_SUCCESS;
	scap_fdinfo *tfdi;

	//
	// Make sure this fd doesn't already exist
	//
	HASH_FIND_INT64(tinfo->fdlist, &(fdi->fd), tfdi);
	if(tfdi != NULL)
	{
		//
		// This can happen if:
		//  - a close() has been dropped when capturing
		//  - an fd has been closed by clone() or execve() (it happens when the fd is opened with the FD_CLOEXEC flag,
		//    which we don't currently parse.
		// In either case, removing the old fd, replacing it with the new one and keeping going is a reasonable
		// choice.
		//
		HASH_DEL(tinfo->fdlist, tfdi);
		free(tfdi);
	}

	//
	// Add the fd to the table, or fire the notification callback
	//
	if(handle->m_proc_callback == NULL)
	{
		HASH_ADD_INT64(tinfo->fdlist, fd, fdi);
		if(uth_status != SCAP_SUCCESS)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (2)");
			return SCAP_FAILURE;
		}
	}
	else
	{
		handle->m_proc_callback(handle->m_proc_callback_context, handle, tinfo->tid, tinfo, fdi);
	}

	return SCAP_SUCCESS;
}

//
// Delete a device entry
//
void scap_dev_delete(scap_t* handle, scap_mountinfo* dev)
{
	//
	// First, remove the process descriptor from the table
	//
	HASH_DEL(handle->m_dev_list, dev);

	//
	// Second, free the memory
	//
	free(dev);
}

//
// Free the device table
//
void scap_free_device_table(scap_t* handle)
{
	scap_mountinfo *dev, *tdev;

	HASH_ITER(hh, handle->m_dev_list, dev, tdev)
	{
		scap_dev_delete(handle, dev);
	}
}

#if defined(HAS_CAPTURE)

int32_t scap_fd_handle_pipe(scap_t *handle, char *fname, scap_threadinfo *tinfo, scap_fdinfo *fdi, char *error)
{
	char link_name[SCAP_MAX_PATH_SIZE];
	ssize_t r;
	uint64_t ino;
	struct stat sb;

	r = readlink(fname, link_name, SCAP_MAX_PATH_SIZE);
	if (r <= 0)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "Could not read link %s (%s)",
			 fname, scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}
	link_name[r] = '\0';
	if(1 != sscanf(link_name, "pipe:[%"PRIi64"]", &ino))
	{
		// in this case we've got a named pipe
		// and we've got to call stat on the link name
		if(-1 == stat(link_name, &sb))
		{
			return SCAP_SUCCESS;
		}
		ino = sb.st_ino;
	}
	strncpy(fdi->info.fname, link_name, SCAP_MAX_PATH_SIZE);

	fdi->ino = ino;
	return scap_add_fd_to_proc_table(handle, tinfo, fdi, error);
}

static inline uint32_t open_flags_to_scap(unsigned long flags)
{
	uint32_t res = 0;

	switch (flags & (O_RDONLY | O_WRONLY | O_RDWR)) {
	case O_WRONLY:
		res |= PPM_O_WRONLY;
		break;
	case O_RDWR:
		res |= PPM_O_RDWR;
		break;
	default:
		res |= PPM_O_RDONLY;
		break;
	}

	if (flags & O_CREAT)
		res |= PPM_O_CREAT;

	if (flags & O_APPEND)
		res |= PPM_O_APPEND;

#ifdef O_DSYNC
	if (flags & O_DSYNC)
		res |= PPM_O_DSYNC;
#endif

	if (flags & O_EXCL)
		res |= PPM_O_EXCL;

	if (flags & O_NONBLOCK)
		res |= PPM_O_NONBLOCK;

	if (flags & O_SYNC)
		res |= PPM_O_SYNC;

	if (flags & O_TRUNC)
		res |= PPM_O_TRUNC;

#ifdef O_DIRECT
	if (flags & O_DIRECT)
		res |= PPM_O_DIRECT;
#endif

#ifdef O_DIRECTORY
	if (flags & O_DIRECTORY)
		res |= PPM_O_DIRECTORY;
#endif

#ifdef O_LARGEFILE
	if (flags & O_LARGEFILE)
		res |= PPM_O_LARGEFILE;
#endif

#ifdef O_CLOEXEC
	if (flags & O_CLOEXEC)
		res |= PPM_O_CLOEXEC;
#endif

	return res;
}

static uint32_t scap_get_device_by_mount_id(scap_t *handle, const char *procdir, unsigned long requested_mount_id)
{
	char fd_dir_name[SCAP_MAX_PATH_SIZE];
	char line[SCAP_MAX_PATH_SIZE];
	FILE *finfo;
	scap_mountinfo *mountinfo;

	HASH_FIND_INT64(handle->m_dev_list, &requested_mount_id, mountinfo);
	if(mountinfo != NULL)
	{
		return mountinfo->dev;
	}

	snprintf(fd_dir_name, SCAP_MAX_PATH_SIZE, "%smountinfo", procdir);
	finfo = fopen(fd_dir_name, "r");
	if(finfo == NULL)
	{
		return 0;
	}

	while(fgets(line, sizeof(line), finfo) != NULL)
	{
		uint32_t mount_id, major, minor;
		if(sscanf(line, "%u %*u %u:%u", &mount_id, &major, &minor) != 3)
		{
			continue;
		}

		if(mount_id == requested_mount_id)
		{
			uint32_t dev = makedev(major, minor);
			mountinfo = malloc(sizeof(*mountinfo));
			if(mountinfo)
			{
				int32_t uth_status = SCAP_SUCCESS;
				mountinfo->mount_id = mount_id;
				mountinfo->dev = dev;
				HASH_ADD_INT64(handle->m_dev_list, mount_id, mountinfo);
				if(uth_status != SCAP_SUCCESS)
				{
					free(mountinfo);
				}
			}
			fclose(finfo);
			return dev;
		}
	}
	fclose(finfo);
	return 0;
}

void scap_fd_flags_file(scap_t *handle, scap_fdinfo *fdi, const char *procdir)
{
	char fd_dir_name[SCAP_MAX_PATH_SIZE];
	char line[SCAP_MAX_PATH_SIZE];
	FILE *finfo;

	snprintf(fd_dir_name, SCAP_MAX_PATH_SIZE, "%sfdinfo/%" PRId64, procdir, fdi->fd);
	finfo = fopen(fd_dir_name, "r");
	if(finfo == NULL)
	{
		return;
	}

	while(fgets(line, sizeof(line), finfo) != NULL)
	{
		// We are interested in the flags and the mnt_id.
		//
		// The format of the file is:
		// pos:    XXXX
		// flags:  YYYYYYYY
		// mnt_id: ZZZ

		if(!strncmp(line, "flags:\t", sizeof("flags:\t") - 1))
		{
			uint32_t open_flags;
			errno = 0;
			unsigned long flags = strtoul(line + sizeof("flags:\t") - 1, NULL, 8);

			if(errno == ERANGE)
			{
				open_flags = PPM_O_NONE;
			}
			else
			{
				open_flags = open_flags_to_scap(flags);
			}

			fdi->info.regularinfo.open_flags = open_flags;
		}
		else if(!strncmp(line, "mnt_id:\t", sizeof("mnt_id:\t") - 1))
		{
			uint32_t dev;
			errno = 0;
			unsigned long mount_id = strtoul(line + sizeof("mnt_id:\t") - 1, NULL, 10);

			if(errno == ERANGE)
			{
				dev = 0;
			}
			else
			{
				dev = scap_get_device_by_mount_id(handle, procdir, mount_id);
			}

			fdi->info.regularinfo.dev = dev;
		}
	}

	fclose(finfo);
}

int32_t scap_fd_handle_regular_file(scap_t *handle, char *fname, scap_threadinfo *tinfo, scap_fdinfo *fdi, const char *procdir, char *error)
{
	char link_name[SCAP_MAX_PATH_SIZE];
	ssize_t r;

	r = readlink(fname, link_name, SCAP_MAX_PATH_SIZE);
	if (r <= 0)
	{
		return SCAP_SUCCESS;
	}

	link_name[r] = '\0';

	if(SCAP_FD_UNSUPPORTED == fdi->type)
	{
		// try to classify by link name
		if(0 == strcmp(link_name,"anon_inode:[eventfd]"))
		{
			fdi->type = SCAP_FD_EVENT;
		}
		else if(0 == strcmp(link_name,"anon_inode:[signalfd]"))
		{
			fdi->type = SCAP_FD_SIGNALFD;
		}
		else if(0 == strcmp(link_name,"anon_inode:[eventpoll]"))
		{
			fdi->type = SCAP_FD_EVENTPOLL;
		}
		else if(0 == strcmp(link_name,"anon_inode:inotify"))
		{
			fdi->type = SCAP_FD_INOTIFY;
		}
		else if(0 == strcmp(link_name,"anon_inode:[timerfd]"))
		{
			fdi->type = SCAP_FD_TIMERFD;
		}


		if(SCAP_FD_UNSUPPORTED == fdi->type)
		{
			// still not able to classify
			// printf("unsupported %s -> %s\n",fname,link_name);
		}
		fdi->info.fname[0] = '\0';
	}
	else if(fdi->type == SCAP_FD_FILE_V2)
	{
		scap_fd_flags_file(handle, fdi, procdir);
		strncpy(fdi->info.regularinfo.fname, link_name, SCAP_MAX_PATH_SIZE);
	}
	else
	{
		strncpy(fdi->info.fname, link_name, SCAP_MAX_PATH_SIZE);
	}

	return scap_add_fd_to_proc_table(handle, tinfo, fdi, error);
}

int32_t scap_fd_handle_socket(scap_t *handle, char *fname, scap_threadinfo *tinfo, scap_fdinfo *fdi, char* procdir, uint64_t net_ns, struct scap_ns_socket_list **sockets_by_ns, char *error)
{
	char link_name[SCAP_MAX_PATH_SIZE];
	ssize_t r;
	scap_fdinfo *tfdi;
	uint64_t ino;
	struct scap_ns_socket_list* sockets = NULL;
	int32_t uth_status = SCAP_SUCCESS;

	if(*sockets_by_ns == (void*)-1)
	{
		return SCAP_SUCCESS;
	}
	else
	{
		HASH_FIND_INT64(*sockets_by_ns, &net_ns, sockets);
		if(sockets == NULL)
		{
			sockets = malloc(sizeof(struct scap_ns_socket_list));
			sockets->net_ns = net_ns;
			sockets->sockets = NULL;
			char fd_error[SCAP_LASTERR_SIZE];

			HASH_ADD_INT64(*sockets_by_ns, net_ns, sockets);
			if(uth_status != SCAP_SUCCESS)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "socket list allocation error");
				free(sockets);
				return SCAP_FAILURE;
			}

			if(scap_fd_read_sockets(handle, procdir, sockets, fd_error) == SCAP_FAILURE)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "Cannot read sockets (%s)", fd_error);
				sockets->sockets = NULL;
				return SCAP_FAILURE;
			}
		}
	}

	r = readlink(fname, link_name, SCAP_MAX_PATH_SIZE);
	if(r <= 0)
	{
		return SCAP_SUCCESS;
	}

	link_name[r] = '\0';

	strncpy(fdi->info.fname, link_name, SCAP_MAX_PATH_SIZE);

	// link name for sockets should be of the format socket:[ino]
	if(1 != sscanf(link_name, "socket:[%"PRIi64"]", &ino))
	{
		// it's a kind of socket, but we don't support it right now
		fdi->type = SCAP_FD_UNSUPPORTED;
		return scap_add_fd_to_proc_table(handle, tinfo, fdi, error);
	}

	//
	// Lookup ino in the list of sockets
	//
	HASH_FIND_INT64(sockets->sockets, &ino, tfdi);
	if(tfdi != NULL)
	{
		memcpy(&(fdi->info), &(tfdi->info), sizeof(fdi->info));
		fdi->ino = ino;
		fdi->type = tfdi->type;
		return scap_add_fd_to_proc_table(handle, tinfo, fdi, error);
	}
	else
	{
		return SCAP_SUCCESS;
	}
}

int32_t scap_fd_read_unix_sockets_from_proc_fs(scap_t *handle, const char* filename, scap_fdinfo **sockets)
{
	FILE *f;
	char line[SCAP_MAX_PATH_SIZE];
	int first_line = false;
	char *delimiters = " \t";
	char *token;
	int32_t uth_status = SCAP_SUCCESS;

	f = fopen(filename, "r");
	if(NULL == f)
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not open sockets file %s (%s)",
			 filename,
			 scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}
	while(NULL != fgets(line, sizeof(line), f))
	{
		char *scratch;

		// skip the first line ... contains field names
		if(!first_line)
		{
			first_line = true;
			continue;
		}
		scap_fdinfo *fdinfo = malloc(sizeof(scap_fdinfo));
		fdinfo->type = SCAP_FD_UNIX_SOCK;


		//
		// parse the fields
		//
		// 1. Num
		token = strtok_r(line, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		fdinfo->info.unix_socket_info.source = strtoul(token, NULL, 16);
		fdinfo->info.unix_socket_info.destination = 0;

		// 2. RefCount
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 3. Protocol
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 4. Flags
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 5. Type
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 6. St
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 7. Inode
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		sscanf(token, "%"PRIu64, &(fdinfo->ino));

		// 8. Path
		token = strtok_r(NULL, delimiters, &scratch);
		if(NULL != token)
		{
			strncpy(fdinfo->info.unix_socket_info.fname, token, SCAP_MAX_PATH_SIZE);
		}
		else
		{
			fdinfo->info.unix_socket_info.fname[0] = '\0';
		}

		HASH_ADD_INT64((*sockets), ino, fdinfo);
		if(uth_status != SCAP_SUCCESS)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "unix socket allocation error");
			fclose(f);
			free(fdinfo);
			return SCAP_FAILURE;
		}
	}
	fclose(f);
	return uth_status;
}

//sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks     Drops     Inode
//ffff88011abfb000 0   0      00000000 0        0        0 2        0        13

int32_t scap_fd_read_netlink_sockets_from_proc_fs(scap_t *handle, const char* filename, scap_fdinfo **sockets)
{
	FILE *f;
	char line[SCAP_MAX_PATH_SIZE];
	int first_line = false;
	char *delimiters = " \t";
	char *token;
	int32_t uth_status = SCAP_SUCCESS;

	f = fopen(filename, "r");
	if(NULL == f)
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not open netlink sockets file %s (%s)",
			 filename,
			 scap_strerror(handle, errno));

		return SCAP_FAILURE;
	}
	while(NULL != fgets(line, sizeof(line), f))
	{
		char *scratch;

		// skip the first line ... contains field names
		if(!first_line)
		{
			first_line = true;
			continue;
		}
		scap_fdinfo *fdinfo = malloc(sizeof(scap_fdinfo));
		memset(fdinfo, 0, sizeof(scap_fdinfo));
		fdinfo->type = SCAP_FD_UNIX_SOCK;


		//
		// parse the fields
		//
		// 1. Num
		token = strtok_r(line, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 2. Eth
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 3. Pid
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 4. Groups
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 5. Rmem
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 6. Wmem
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 7. Dump
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 8. Locks
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 9. Drops
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 10. Inode
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		sscanf(token, "%"PRIu64, &(fdinfo->ino));

		HASH_ADD_INT64((*sockets), ino, fdinfo);
		if(uth_status != SCAP_SUCCESS)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "netlink socket allocation error");
			fclose(f);
			free(fdinfo);
			return SCAP_FAILURE;
		}
	}
	fclose(f);
	return uth_status;
}

int32_t scap_fd_read_ipv4_sockets_from_proc_fs(scap_t *handle, const char *dir, int l4proto, scap_fdinfo **sockets)
{
	FILE *f;
	int32_t uth_status = SCAP_SUCCESS;
	char* scan_buf;
	char* scan_pos;
	char* tmp_pos;
	uint32_t rsize;
	char* end;
	char tc;
	uint32_t j;

	scan_buf = (char*)malloc(SOCKET_SCAN_BUFFER_SIZE);
	if(scan_buf == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scan_buf allocation error");
		return SCAP_FAILURE;
	}

	f = fopen(dir, "r");
	if(NULL == f)
	{
		ASSERT(false);
		free(scan_buf);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not open ipv4 sockets dir %s (%s)",
			 dir,
			 scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}

	while((rsize = fread(scan_buf, 1, SOCKET_SCAN_BUFFER_SIZE, f))  != 0)
	{
		char* scan_end = scan_buf + rsize;
		scan_pos = scan_buf;

		while(scan_pos <= scan_end)
		{
			scan_pos = memchr(scan_pos, '\n', scan_end - scan_pos);

			if(scan_pos == NULL)
			{
				break;
			}

			scap_fdinfo *fdinfo = malloc(sizeof(scap_fdinfo));

			//
			// Skip the sl field
			//
			scan_pos = memchr(scan_pos, ':', scan_end - scan_pos);
			if(scan_pos == NULL)
			{
				free(fdinfo);
				break;
			}

			scan_pos += 2;
			if(scan_pos + 80 >= scan_end)
			{
				free(fdinfo);
				break;
			}

			//
			// Scan the local address
			//
			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv4info.sip = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 9;
			tc = *(scan_pos + 4);
			ASSERT(tc == ' ');
			*(scan_pos + 4) = 0;
			fdinfo->info.ipv4info.sport = (uint16_t)strtoul(scan_pos, &end, 16);
			*(scan_pos + 4) = tc;

			//
			// Scan the remote address
			//
			scan_pos += 5;

			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv4info.dip = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 9;
			tc = *(scan_pos + 4);
			ASSERT(tc == ' ');
			*(scan_pos + 4) = 0;
			fdinfo->info.ipv4info.dport = (uint16_t)strtoul(scan_pos, &end, 16);
			*(scan_pos + 4) = tc;

			//
			// Skip to parsing the inode
			//
			scan_pos += 4;

			for(j = 0; j < 6; j++)
			{
				scan_pos++;

				scan_pos = memchr(scan_pos, ' ', scan_end - scan_pos);
				if(scan_pos == NULL)
				{
					break;
				}

				while(*scan_pos == ' ' && scan_pos < scan_end)
				{
					scan_pos++;
				}

				if(scan_pos >= scan_end)
				{
					break;
				}
			}

			if(j < 6)
			{
				free(fdinfo);
				break;
			}

			tmp_pos = scan_pos;
			scan_pos = memchr(scan_pos, ' ', scan_end - scan_pos);
			if(scan_pos == NULL || scan_pos >= scan_end)
			{
				free(fdinfo);
				break;
			}

			tc = *(scan_pos);

			fdinfo->ino = (uint64_t)strtoull(tmp_pos, &end, 10);

			*(scan_pos) = tc;

			//
			// Add to the table
			//
			if(fdinfo->info.ipv4info.dip == 0)
			{
				fdinfo->type = SCAP_FD_IPV4_SERVSOCK;
				fdinfo->info.ipv4serverinfo.l4proto = l4proto;
				fdinfo->info.ipv4serverinfo.port = fdinfo->info.ipv4info.sport;
				fdinfo->info.ipv4serverinfo.ip = fdinfo->info.ipv4info.sip;
			}
			else
			{
				fdinfo->type = SCAP_FD_IPV4_SOCK;
				fdinfo->info.ipv4info.l4proto = l4proto;
			}

			HASH_ADD_INT64((*sockets), ino, fdinfo);

			if(uth_status != SCAP_SUCCESS)
			{
				uth_status = SCAP_FAILURE;
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "ipv4 socket allocation error");
				free(fdinfo);
				break;
			}

			scan_pos++;
		}
	}

	fclose(f);
	free(scan_buf);
	return uth_status;
}

int32_t scap_fd_is_ipv6_server_socket(uint32_t ip6_addr[4])
{
	return 0 == ip6_addr[0] && 0 == ip6_addr[1] && 0 == ip6_addr[2] && 0 == ip6_addr[3];
}

int32_t scap_fd_read_ipv6_sockets_from_proc_fs(scap_t *handle, char *dir, int l4proto, scap_fdinfo **sockets)
{
	FILE *f;
	int32_t uth_status = SCAP_SUCCESS;
	char* scan_buf;
	char* scan_pos;
	char* tmp_pos;
	uint32_t rsize;
	char* end;
	char tc;
	uint32_t j;

	scan_buf = (char*)malloc(SOCKET_SCAN_BUFFER_SIZE);
	if(scan_buf == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scan_buf allocation error");
		return SCAP_FAILURE;
	}

	f = fopen(dir, "r");

	if(NULL == f)
	{
		ASSERT(false);
		free(scan_buf);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not open ipv6 sockets dir %s (%s)",
			 dir,
			 scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}

	while((rsize = fread(scan_buf, 1, SOCKET_SCAN_BUFFER_SIZE, f))  != 0)
	{
		char* scan_end = scan_buf + rsize;
		scan_pos = scan_buf;

		while(scan_pos <= scan_end)
		{
			scan_pos = memchr(scan_pos, '\n', scan_end - scan_pos);

			if(scan_pos == NULL)
			{
				break;
			}

			scap_fdinfo *fdinfo = malloc(sizeof(scap_fdinfo));

			//
			// Skip the sl field
			//
			scan_pos = memchr(scan_pos, ':', scan_end - scan_pos);
			if(scan_pos == NULL)
			{
				free(fdinfo);
				break;
			}

			scan_pos += 2;
			if(scan_pos + 80 >= scan_end)
			{
				free(fdinfo);
				break;
			}

			//
			// Scan the first address
			//
			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.sip[0] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 8;
			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.sip[1] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 8;
			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.sip[2] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 8;
			tc = *(scan_pos + 8);
			ASSERT(tc == ':');
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.sip[3] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 9;
			tc = *(scan_pos + 4);
			ASSERT(tc == ' ');
			*(scan_pos + 4) = 0;
			fdinfo->info.ipv6info.sport = (uint16_t)strtoul(scan_pos, &end, 16);
			*(scan_pos + 4) = tc;

			//
			// Scan the second address
			//
			scan_pos += 5;

			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.dip[0] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 8;
			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.dip[1] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 8;
			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.dip[2] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 8;
			tc = *(scan_pos + 8);
			ASSERT(tc == ':');
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.dip[3] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 9;
			tc = *(scan_pos + 4);
			ASSERT(tc == ' ');
			*(scan_pos + 4) = 0;
			fdinfo->info.ipv6info.dport = (uint16_t)strtoul(scan_pos, &end, 16);
			*(scan_pos + 4) = tc;

			//
			// Skip to parsing the inode
			//
			scan_pos += 4;

			for(j = 0; j < 6; j++)
			{
				scan_pos++;

				scan_pos = memchr(scan_pos, ' ', scan_end - scan_pos);
				if(scan_pos == NULL)
				{
					break;
				}

				while(*scan_pos == ' ' && scan_pos < scan_end)
				{
					scan_pos++;
				}

				if(scan_pos >= scan_end)
				{
					break;
				}
			}

			if(j < 6)
			{
				free(fdinfo);
				break;
			}

			tmp_pos = scan_pos;
			scan_pos = memchr(scan_pos, ' ', scan_end - scan_pos);
			if(scan_pos == NULL || scan_pos >= scan_end)
			{
				free(fdinfo);
				break;
			}

			tc = *(scan_pos);

			fdinfo->ino = (uint64_t)strtoull(tmp_pos, &end, 10);

			*(scan_pos) = tc;

			//
			// Add to the table
			//
			if(scap_fd_is_ipv6_server_socket(fdinfo->info.ipv6info.dip))
			{
				fdinfo->type = SCAP_FD_IPV6_SERVSOCK;
				fdinfo->info.ipv6serverinfo.l4proto = l4proto;
				fdinfo->info.ipv6serverinfo.port = fdinfo->info.ipv6info.sport;
				fdinfo->info.ipv6serverinfo.ip[0] = fdinfo->info.ipv6info.sip[0];
				fdinfo->info.ipv6serverinfo.ip[1] = fdinfo->info.ipv6info.sip[1];
				fdinfo->info.ipv6serverinfo.ip[2] = fdinfo->info.ipv6info.sip[2];
				fdinfo->info.ipv6serverinfo.ip[3] = fdinfo->info.ipv6info.sip[3];
			}
			else
			{
				fdinfo->type = SCAP_FD_IPV6_SOCK;
				fdinfo->info.ipv6info.l4proto = l4proto;
			}

			HASH_ADD_INT64((*sockets), ino, fdinfo);

			if(uth_status != SCAP_SUCCESS)
			{
				uth_status = SCAP_FAILURE;
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "ipv6 socket allocation error");
				break;
			}

			scan_pos++;
		}
	}

	fclose(f);
	free(scan_buf);

	return uth_status;
}

int32_t scap_fd_read_sockets(scap_t *handle, char* procdir, struct scap_ns_socket_list *sockets, char *error)
{
	char filename[SCAP_MAX_PATH_SIZE];
	char netroot[SCAP_MAX_PATH_SIZE];

	if(sockets->net_ns)
	{
		//
		// Namespace support, look in /proc/PID/net/
		//
		snprintf(netroot, sizeof(netroot), "%snet/", procdir);
	}
	else
	{
		//
		// No namespace support, look in the base /proc
		//
		snprintf(netroot, sizeof(netroot), "%s/proc/net/", scap_get_host_root());
	}

	snprintf(filename, sizeof(filename), "%stcp", netroot);
	if(scap_fd_read_ipv4_sockets_from_proc_fs(handle, filename, SCAP_L4_TCP, &sockets->sockets) == SCAP_FAILURE)
	{
		scap_fd_free_table(handle, &sockets->sockets);
		snprintf(error, SCAP_LASTERR_SIZE, "Could not read ipv4 tcp sockets (%s)", handle->m_lasterr);
		return SCAP_FAILURE;
	}

	snprintf(filename, sizeof(filename), "%sudp", netroot);
	if(scap_fd_read_ipv4_sockets_from_proc_fs(handle, filename, SCAP_L4_UDP, &sockets->sockets) == SCAP_FAILURE)
	{
		scap_fd_free_table(handle, &sockets->sockets);
		snprintf(error, SCAP_LASTERR_SIZE, "Could not read ipv4 udp sockets (%s)", handle->m_lasterr);
		return SCAP_FAILURE;
	}

	snprintf(filename, sizeof(filename), "%sraw", netroot);
	if(scap_fd_read_ipv4_sockets_from_proc_fs(handle, filename, SCAP_L4_RAW, &sockets->sockets) == SCAP_FAILURE)
	{
		scap_fd_free_table(handle, &sockets->sockets);
		snprintf(error, SCAP_LASTERR_SIZE, "Could not read ipv4 raw sockets (%s)", handle->m_lasterr);
		return SCAP_FAILURE;
	}

	snprintf(filename, sizeof(filename), "%sunix", netroot);
	if(scap_fd_read_unix_sockets_from_proc_fs(handle, filename, &sockets->sockets) == SCAP_FAILURE)
	{
		scap_fd_free_table(handle, &sockets->sockets);
		snprintf(error, SCAP_LASTERR_SIZE, "Could not read unix sockets (%s)", handle->m_lasterr);
		return SCAP_FAILURE;
	}

	snprintf(filename, sizeof(filename), "%snetlink", netroot);
	if(scap_fd_read_netlink_sockets_from_proc_fs(handle, filename, &sockets->sockets) == SCAP_FAILURE)
	{
		scap_fd_free_table(handle, &sockets->sockets);
		snprintf(error, SCAP_LASTERR_SIZE, "Could not read netlink sockets (%s)", handle->m_lasterr);
		return SCAP_FAILURE;
	}

	snprintf(filename, sizeof(filename), "%stcp6", netroot);
    /* We assume if there is /proc/net/tcp6 that ipv6 is available */
    if(access(filename, R_OK) == 0)
    {
		if(scap_fd_read_ipv6_sockets_from_proc_fs(handle, filename, SCAP_L4_TCP, &sockets->sockets) == SCAP_FAILURE)
		{
			scap_fd_free_table(handle, &sockets->sockets);
			snprintf(error, SCAP_LASTERR_SIZE, "Could not read ipv6 tcp sockets (%s)", handle->m_lasterr);
			return SCAP_FAILURE;
		}

		snprintf(filename, sizeof(filename), "%sudp6", netroot);
		if(scap_fd_read_ipv6_sockets_from_proc_fs(handle, filename, SCAP_L4_UDP, &sockets->sockets) == SCAP_FAILURE)
		{
			scap_fd_free_table(handle, &sockets->sockets);
			snprintf(error, SCAP_LASTERR_SIZE, "Could not read ipv6 udp sockets (%s)", handle->m_lasterr);
			return SCAP_FAILURE;
		}

		snprintf(filename, sizeof(filename), "%sraw6", netroot);
		if(scap_fd_read_ipv6_sockets_from_proc_fs(handle, filename, SCAP_L4_RAW, &sockets->sockets) == SCAP_FAILURE)
		{
			scap_fd_free_table(handle, &sockets->sockets);
			snprintf(error, SCAP_LASTERR_SIZE, "Could not read ipv6 raw sockets (%s)", handle->m_lasterr);
			return SCAP_FAILURE;
		}
    }

	return SCAP_SUCCESS;
}

int32_t scap_fd_allocate_fdinfo(scap_t *handle, scap_fdinfo **fdi, int64_t fd, scap_fd_type type)
{
	ASSERT(NULL == *fdi);
	*fdi = (scap_fdinfo *)malloc(sizeof(scap_fdinfo));
	if(*fdi == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "fd table allocation error (2)");
		return SCAP_FAILURE;
	}
	(*fdi)->type = type;
	(*fdi)->fd = fd;
	return SCAP_SUCCESS;
}

void scap_fd_free_fdinfo(scap_fdinfo **fdi)
{
	if(NULL != *fdi)
	{
		free(*fdi);
		*fdi = NULL;
	}
}

char * decode_st_mode(struct stat* sb)
{
	switch(sb->st_mode & S_IFMT) {
    case S_IFBLK:
    	return "block device";
    	break;
    case S_IFCHR:
    	return "character device";
    	break;
    case S_IFDIR:
    	return "directory";
    	break;
    case S_IFIFO:
    	return "FIFO/pipe";
    	break;
    case S_IFLNK:
    	return "symlink";
    	break;
    case S_IFREG:
    	return "regular file";
    	break;
    case S_IFSOCK:
    	return "socket";
    	break;
    default:
    	return "unknown?";
    	break;
    }
}
//
// Scan the directory containing the fd's of a proc /proc/x/fd
//
int32_t scap_fd_scan_fd_dir(scap_t *handle, char *procdir, scap_threadinfo *tinfo, struct scap_ns_socket_list **sockets_by_ns, char *error)
{
	DIR *dir_p;
	struct dirent *dir_entry_p;
	int32_t res = SCAP_SUCCESS;
	char fd_dir_name[SCAP_MAX_PATH_SIZE];
	char f_name[SCAP_MAX_PATH_SIZE];
	char link_name[SCAP_MAX_PATH_SIZE];
	struct stat sb;
	uint64_t fd;
	scap_fdinfo *fdi = NULL;
	uint64_t net_ns;
	ssize_t r;
	uint16_t fd_added = 0;

	snprintf(fd_dir_name, SCAP_MAX_PATH_SIZE, "%sfd", procdir);
	dir_p = opendir(fd_dir_name);
	if(dir_p == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error opening the directory %s", fd_dir_name);
		return SCAP_NOTFOUND;
	}

	//
	// Get the network namespace of the process
	//
	snprintf(f_name, sizeof(f_name), "%sns/net", procdir);
	r = readlink(f_name, link_name, sizeof(link_name));
	if(r <= 0)
	{
		//
		// No network namespace available. Assume global
		//
		net_ns = 0;
	}
	else
	{
		link_name[r] = '\0';
		sscanf(link_name, "net:[%"PRIi64"]", &net_ns);
	}

	while((dir_entry_p = readdir(dir_p)) != NULL &&
		(handle->m_fd_lookup_limit == 0 || fd_added < handle->m_fd_lookup_limit))
	{
		fdi = NULL;
		snprintf(f_name, SCAP_MAX_PATH_SIZE, "%s/%s", fd_dir_name, dir_entry_p->d_name);

		if(-1 == stat(f_name, &sb) || 1 != sscanf(dir_entry_p->d_name, "%"PRIu64, &fd))
		{
			continue;
		}

		// In no driver mode to limit cpu usage we just parse sockets
		// because we are interested only on them
		if(handle->m_mode == SCAP_MODE_NODRIVER && !S_ISSOCK(sb.st_mode))
		{
			continue;
		}

		switch(sb.st_mode & S_IFMT)
		{
		case S_IFIFO:
			res = scap_fd_allocate_fdinfo(handle, &fdi, fd, SCAP_FD_FIFO);
			if(SCAP_FAILURE == res)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't allocate scap fd handle for fifo fd %" PRIu64, fd);
				break;
			}
			res = scap_fd_handle_pipe(handle, f_name, tinfo, fdi, error);
			break;
		case S_IFREG:
		case S_IFBLK:
		case S_IFCHR:
		case S_IFLNK:
			res = scap_fd_allocate_fdinfo(handle, &fdi, fd, SCAP_FD_FILE_V2);
			if(SCAP_FAILURE == res)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't allocate scap fd handle for file fd %" PRIu64, fd);
				break;
			}
			fdi->ino = sb.st_ino;
			res = scap_fd_handle_regular_file(handle, f_name, tinfo, fdi, procdir, error);
			break;
		case S_IFDIR:
			res = scap_fd_allocate_fdinfo(handle, &fdi, fd, SCAP_FD_DIRECTORY);
			if(SCAP_FAILURE == res)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't allocate scap fd handle for dir fd %" PRIu64, fd);
				break;
			}
			fdi->ino = sb.st_ino;
			res = scap_fd_handle_regular_file(handle, f_name, tinfo, fdi, procdir, error);
			break;
		case S_IFSOCK:
			res = scap_fd_allocate_fdinfo(handle, &fdi, fd, SCAP_FD_UNKNOWN);
			if(SCAP_FAILURE == res)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't allocate scap fd handle for sock fd %" PRIu64, fd);
				break;
			}
			res = scap_fd_handle_socket(handle, f_name, tinfo, fdi, procdir, net_ns, sockets_by_ns, error);
			if(handle->m_proc_callback == NULL)
			{
				// we can land here if we've got a netlink socket
				if(fdi->type == SCAP_FD_UNKNOWN)
				{
					scap_fd_free_fdinfo(&fdi);
				}
			}
			break;
		default:
			res = scap_fd_allocate_fdinfo(handle, &fdi, fd, SCAP_FD_UNSUPPORTED);
			if(SCAP_FAILURE == res)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't allocate scap fd handle for unsupported fd %" PRIu64, fd);
				break;
			}
			fdi->ino = sb.st_ino;
			res = scap_fd_handle_regular_file(handle, f_name, tinfo, fdi, procdir, error);
			break;
		}

		if(handle->m_proc_callback != NULL)
		{
			if(fdi)
			{
				scap_fd_free_fdinfo(&fdi);
			}
		}

		if(SCAP_SUCCESS != res)
		{
			break;
		} else {
			++fd_added;
		}
	}
	closedir(dir_p);
	return res;
}


#endif // HAS_CAPTURE

//
// Internal helper function to output the fd table of a process
//
void scap_fd_print_table(scap_t *handle, scap_threadinfo *tinfo)
{
	scap_fd_print_fd_table(handle, tinfo->fdlist);
}

void scap_fd_print_fd_table(scap_t *handle, scap_fdinfo *fds)
{
	scap_fdinfo *fdi;
	scap_fdinfo *tfdi;
	char str[SCAP_MAX_PATH_SIZE];

	HASH_ITER(hh, fds, fdi, tfdi)
	{
		if(scap_fd_info_to_string(handle, fdi, str, SCAP_MAX_PATH_SIZE) != SCAP_SUCCESS)
		{
			ASSERT(false);
			snprintf(str, SCAP_MAX_PATH_SIZE, "N.A.");
		}
		fprintf(stderr, "  %"PRIu64") %s\n", fdi->fd, str);
	}
}

