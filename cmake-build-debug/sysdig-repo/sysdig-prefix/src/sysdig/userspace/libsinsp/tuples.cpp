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

#include <tuples.h>

ipv6addr ipv6addr::empty_address = {0x00000000, 0x00000000, 0x00000000, 0x00000000};

bool ipv6addr::operator==(const ipv6addr &other) const
{
	return (m_b[0] == other.m_b[0] &&
		m_b[1] == other.m_b[1] &&
		m_b[2] == other.m_b[2] &&
		m_b[3] == other.m_b[3]);
}

bool ipv6addr::operator!=(const ipv6addr &other) const
{
	return !operator==(other);
}

bool ipv6addr::operator<(const ipv6addr &other) const
{
	for(int i = 0; i < 4; i++)
	{
		if(m_b[i] < other.m_b[i]) return true;
		else if(other.m_b[i] < m_b[i]) return false;
	}
	return false;
}

bool ipv6addr::in_subnet(const ipv6addr &other) const
{
	// They're in the same subnet if the first 64 bits match
	// (Assumes convention of first 48 bits for network, next 16
	// bits for subnet).
	return (m_b[0] == other.m_b[0] &&
		m_b[1] == other.m_b[1]);
}
