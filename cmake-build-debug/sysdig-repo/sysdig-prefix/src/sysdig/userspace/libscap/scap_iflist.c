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

#include "scap.h"
#include "scap-int.h"

#if defined(HAS_CAPTURE)
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <errno.h>

//
// Allocate and return the list of interfaces on this system
//
int32_t scap_create_iflist(scap_t* handle)
{
	struct ifaddrs *interfaceArray = NULL, *tempIfAddr = NULL;
	void *tempAddrPtr = NULL;
	int rc = 0;
	uint32_t ifcnt4 = 0;
	uint32_t ifcnt6 = 0;

	//
	// If the list of interfaces was already allocated for this handle (for example because this is
	// not the first interface list block), free it
	//
	if(handle->m_addrlist != NULL)
	{
		scap_free_iflist(handle->m_addrlist);
		handle->m_addrlist = NULL;
	}

	rc = getifaddrs(&interfaceArray);  /* retrieve the current interfaces */
	if(rc != 0)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "getifaddrs failed");
		return SCAP_FAILURE;
	}

	//
	// First pass: count the number of interfaces
	//
	for(tempIfAddr = interfaceArray; tempIfAddr != NULL; tempIfAddr = tempIfAddr->ifa_next)
	{
		if(tempIfAddr->ifa_addr == NULL)
		{
			// "eql" interface like on EC2
			continue;
		}
		
		if(tempIfAddr->ifa_addr->sa_family == AF_INET)
		{
			ifcnt4++;
		}
		else if(tempIfAddr->ifa_addr->sa_family == AF_INET6)
		{
			ifcnt6++;
		}
	}

	//
	// Allocate the handle and the arrays
	//
	handle->m_addrlist = (scap_addrlist*)malloc(sizeof(scap_addrlist));
	if(!handle->m_addrlist)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "getifaddrs allocation failed(1)");
		return SCAP_FAILURE;
	}

	if(ifcnt4 != 0)
	{
		handle->m_addrlist->v4list = (scap_ifinfo_ipv4*)malloc(ifcnt4 * sizeof(scap_ifinfo_ipv4));
		if(!handle->m_addrlist->v4list)
		{
			snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "getifaddrs allocation failed(2)");
			free(handle->m_addrlist);
			return SCAP_FAILURE;
		}
	}
	else
	{
		handle->m_addrlist->v4list = NULL;
	}

	if(ifcnt6 != 0)
	{
		handle->m_addrlist->v6list = (scap_ifinfo_ipv6*)malloc(ifcnt6 * sizeof(scap_ifinfo_ipv6));
		if(!handle->m_addrlist->v6list)
		{
			snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "getifaddrs allocation failed(3)");
			if(handle->m_addrlist->v4list)
			{
				free(handle->m_addrlist->v4list);
			}
			free(handle->m_addrlist);
			return SCAP_FAILURE;
		}
	}
	else
	{
		handle->m_addrlist->v6list = NULL;
	}

	handle->m_addrlist->n_v4_addrs = ifcnt4;
	handle->m_addrlist->n_v6_addrs = ifcnt6;

	//
	// Second pass: populate the arrays
	//
	handle->m_addrlist->totlen = 0;
	ifcnt4 = 0;
	ifcnt6 = 0;

	for(tempIfAddr = interfaceArray; tempIfAddr != NULL; tempIfAddr = tempIfAddr->ifa_next)
	{
		if(tempIfAddr->ifa_addr == NULL)
		{
			// "eql" interface like on EC2
			continue;
		}

		if(tempIfAddr->ifa_addr->sa_family == AF_INET)
		{
			handle->m_addrlist->v4list[ifcnt4].type = SCAP_II_IPV4;

			tempAddrPtr = &((struct sockaddr_in *)tempIfAddr->ifa_addr)->sin_addr;
			handle->m_addrlist->v4list[ifcnt4].addr = *(uint32_t*)tempAddrPtr;

			if(tempIfAddr->ifa_netmask != NULL)
			{
				handle->m_addrlist->v4list[ifcnt4].netmask = *(uint32_t*)&(((struct sockaddr_in *)tempIfAddr->ifa_netmask)->sin_addr);
			}
			else
			{
				handle->m_addrlist->v4list[ifcnt4].netmask = 0;
			}

#ifndef CYGWING_AGENT
			if(tempIfAddr->ifa_ifu.ifu_broadaddr != NULL)
			{
				handle->m_addrlist->v4list[ifcnt4].bcast = *(uint32_t*)&(((struct sockaddr_in *)tempIfAddr->ifa_ifu.ifu_broadaddr)->sin_addr);
			}
			else
			{
				handle->m_addrlist->v4list[ifcnt4].bcast = 0;
			}
#else
			handle->m_addrlist->v4list[ifcnt4].bcast = 0;
#endif
			strncpy(handle->m_addrlist->v4list[ifcnt4].ifname, tempIfAddr->ifa_name, SCAP_MAX_PATH_SIZE);
			handle->m_addrlist->v4list[ifcnt4].ifnamelen = strlen(tempIfAddr->ifa_name);

			handle->m_addrlist->v4list[ifcnt4].linkspeed = 0;

			handle->m_addrlist->totlen += (sizeof(scap_ifinfo_ipv4) + handle->m_addrlist->v4list[ifcnt4].ifnamelen - SCAP_MAX_PATH_SIZE);
			ifcnt4++;
		}
		else if(tempIfAddr->ifa_addr->sa_family == AF_INET6)
		{
			handle->m_addrlist->v6list[ifcnt6].type = SCAP_II_IPV6;

			tempAddrPtr = &((struct sockaddr_in6 *)tempIfAddr->ifa_addr)->sin6_addr;

			memcpy(handle->m_addrlist->v6list[ifcnt6].addr, tempAddrPtr, 16);

			if(tempIfAddr->ifa_netmask != NULL)
			{
				memcpy(handle->m_addrlist->v6list[ifcnt6].netmask,
						&(((struct sockaddr_in6 *)tempIfAddr->ifa_netmask)->sin6_addr),
						16);
			}
			else
			{
				memset(handle->m_addrlist->v6list[ifcnt6].netmask, 0, 16);
			}

#ifndef CYGWING_AGENT
			if(tempIfAddr->ifa_ifu.ifu_broadaddr != NULL)
			{
				memcpy(handle->m_addrlist->v6list[ifcnt6].bcast,
						&(((struct sockaddr_in6 *)tempIfAddr->ifa_ifu.ifu_broadaddr)->sin6_addr),
						16);
			}
			else
			{
				memset(handle->m_addrlist->v6list[ifcnt6].bcast, 0, 16);
			}
#else
			handle->m_addrlist->v4list[ifcnt4].bcast = 0;
#endif

			strncpy(handle->m_addrlist->v6list[ifcnt6].ifname, tempIfAddr->ifa_name, SCAP_MAX_PATH_SIZE);
			handle->m_addrlist->v6list[ifcnt6].ifnamelen = strlen(tempIfAddr->ifa_name);

			handle->m_addrlist->v6list[ifcnt6].linkspeed = 0;

			handle->m_addrlist->totlen += (sizeof(scap_ifinfo_ipv6) + handle->m_addrlist->v6list[ifcnt6].ifnamelen - SCAP_MAX_PATH_SIZE);
			ifcnt6++;
		}
		else
		{
			continue;
		}
	}

	//
	// Memory cleanup
	//
	freeifaddrs(interfaceArray);

	return SCAP_SUCCESS;
}

void scap_refresh_iflist(scap_t* handle)
{
	scap_free_iflist(handle->m_addrlist);
	handle->m_addrlist = NULL;
	scap_create_iflist(handle);
}
#endif // HAS_CAPTURE

//
// Free a previously allocated list of interfaces
//
void scap_free_iflist(scap_addrlist* ifhandle)
{
	if(ifhandle)
	{
		if(ifhandle->v6list)
		{
			free(ifhandle->v6list);
		}

		if(ifhandle->v4list)
		{
			free(ifhandle->v4list);
		}

		free(ifhandle);
	}
}
