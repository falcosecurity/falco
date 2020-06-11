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

#ifndef _GNU_SOURCE
#include <string.h>

void *memmem(const void *haystack, size_t haystacklen,
	const void *needle, size_t needlelen)
{
	const unsigned char *ptr;
	const unsigned char *end;

	if(needlelen == 0)
	{
		return (void *)haystack;
	}

	if(haystacklen < needlelen)
	{
		return NULL;
	}

	end = (const unsigned char *)haystack + haystacklen - needlelen;
	for(ptr = (const unsigned char *)haystack; ptr <= end; ptr++)
	{
		if(!memcmp(ptr, needle, needlelen))
		{
			return (void *)ptr;
		}
	}

	return NULL;
}
#endif
