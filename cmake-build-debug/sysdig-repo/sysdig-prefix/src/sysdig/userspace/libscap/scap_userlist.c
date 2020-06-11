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

#include <pwd.h>
#include <grp.h>

//
// Allocate and return the list of users on this system
//
int32_t scap_create_userlist(scap_t* handle)
{
	uint32_t usercnt;
	uint32_t grpcnt;
	struct passwd *p;
	struct group *g;

	//
	// If the list of users was already allocated for this handle (for example because this is
	// not the first user list block), free it
	//
	if(handle->m_userlist != NULL)
	{
		scap_free_userlist(handle->m_userlist);
		handle->m_userlist = NULL;
	}

	//
	// First pass: count the number of users and the number of groups
	//
	setpwent();
	p = getpwent();
	for(usercnt = 0; p; p = getpwent(), usercnt++); 
	endpwent();

	setgrent();
	g = getgrent();
	for(grpcnt = 0; g; g = getgrent(), grpcnt++);
	endgrent();

	//
	// Memory allocations
	//
	handle->m_userlist = (scap_userlist*)malloc(sizeof(scap_userlist));
	if(handle->m_userlist == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation failed(1)");
		return SCAP_FAILURE;
	}

	handle->m_userlist->nusers = usercnt;
	handle->m_userlist->ngroups = grpcnt;
	handle->m_userlist->totsavelen = 0;
	handle->m_userlist->users = (scap_userinfo*)malloc(usercnt * sizeof(scap_userinfo));
	if(handle->m_userlist->users == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation failed(2)");
		free(handle->m_userlist);
		return SCAP_FAILURE;		
	}

	handle->m_userlist->groups = (scap_groupinfo*)malloc(grpcnt * sizeof(scap_groupinfo));
	if(handle->m_userlist->groups == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "grouplist allocation failed(2)");
		free(handle->m_userlist->users);
		free(handle->m_userlist);
		return SCAP_FAILURE;		
	}

	//
	// Second pass: copy the data
	//

	//users
	setpwent();
	p = getpwent();

	for(usercnt = 0; p; p = getpwent(), usercnt++)
	{
		handle->m_userlist->users[usercnt].uid = p->pw_uid;
		handle->m_userlist->users[usercnt].gid = p->pw_gid;
		
		if(p->pw_name)
		{
			strncpy(handle->m_userlist->users[usercnt].name, p->pw_name, sizeof(handle->m_userlist->users[usercnt].name));
		}
		else
		{
			*handle->m_userlist->users[usercnt].name = '\0';
		}

		if(p->pw_dir)
		{
			strncpy(handle->m_userlist->users[usercnt].homedir, p->pw_dir, sizeof(handle->m_userlist->users[usercnt].homedir));
		}
		else
		{
			*handle->m_userlist->users[usercnt].homedir = '\0';	
		}

		if(p->pw_shell)
		{
			strncpy(handle->m_userlist->users[usercnt].shell, p->pw_shell, sizeof(handle->m_userlist->users[usercnt].shell));
		}
		else
		{
			*handle->m_userlist->users[usercnt].shell = '\0';	
		}

		handle->m_userlist->totsavelen += 
			sizeof(uint8_t) + // type
			sizeof(uint32_t) + // uid
			sizeof(uint32_t) +  // gid
			strlen(handle->m_userlist->users[usercnt].name) + 2 + 
			strlen(handle->m_userlist->users[usercnt].homedir) + 2 +
			strlen(handle->m_userlist->users[usercnt].shell) + 2; 
	}

	endpwent();

	// groups
	setgrent();
	g = getgrent();

	for(grpcnt = 0; g; g = getgrent(), grpcnt++)
	{
		handle->m_userlist->groups[grpcnt].gid = g->gr_gid;

		if(g->gr_name)
		{
			strncpy(handle->m_userlist->groups[grpcnt].name, g->gr_name, sizeof(handle->m_userlist->groups[grpcnt].name));
		}
		else
		{
			*handle->m_userlist->groups[grpcnt].name = '\0';
		}

		handle->m_userlist->totsavelen += 
			sizeof(uint8_t) + // type
			sizeof(uint32_t) +  // gid
			strlen(handle->m_userlist->groups[grpcnt].name) + 2;
	}

	endgrent();

	return SCAP_SUCCESS;
}
#endif // HAS_CAPTURE

//
// Free a previously allocated list of users
//
void scap_free_userlist(scap_userlist* uhandle)
{
	if(uhandle)
	{
		free(uhandle->users);
		free(uhandle->groups);
		free(uhandle);
	}
}
