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

#include <time.h>
#ifndef _WIN32
#include <algorithm>
#endif
#include "sinsp.h"
#include "sinsp_int.h"
#include "protodecoder.h"

extern sinsp_protodecoder_list g_decoderlist;

///////////////////////////////////////////////////////////////////////////////
// sinsp_protodecoder implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_protodecoder::sinsp_protodecoder()
{
}

void sinsp_protodecoder::set_inspector(sinsp* inspector)
{
	m_inspector = inspector;
}

void sinsp_protodecoder::on_read(sinsp_evt* evt, char *data, uint32_t len)
{
	ASSERT(false);
}

void sinsp_protodecoder::on_write(sinsp_evt* evt, char *data, uint32_t len)
{
	ASSERT(false);
}

void sinsp_protodecoder::on_reset(sinsp_evt* evt)
{
	ASSERT(false);
}

void sinsp_protodecoder::register_event_callback(sinsp_pd_callback_type etype)
{
	ASSERT(m_inspector != NULL);

	m_inspector->m_parser->register_event_callback(etype, this);
}

void sinsp_protodecoder::register_read_callback(sinsp_fdinfo_t* fdinfo)
{
	ASSERT(m_inspector != NULL);

	fdinfo->register_event_callback(CT_READ, this);
}

void sinsp_protodecoder::register_write_callback(sinsp_fdinfo_t* fdinfo)
{
	ASSERT(m_inspector != NULL);

	fdinfo->register_event_callback(CT_WRITE, this);
}

void sinsp_protodecoder::unregister_read_callback(sinsp_fdinfo_t* fdinfo)
{
	ASSERT(m_inspector != NULL);

	fdinfo->unregister_event_callback(CT_READ, this);
}

void sinsp_protodecoder::unregister_write_callback(sinsp_fdinfo_t* fdinfo)
{
	ASSERT(m_inspector != NULL);

	fdinfo->unregister_event_callback(CT_WRITE, this);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_protodecoder_list implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_protodecoder_list::sinsp_protodecoder_list()
{
	//////////////////////////////////////////////////////////////////////////////
	// ADD NEW DECODER CLASSES HERE
	//////////////////////////////////////////////////////////////////////////////
	add_protodecoder(new sinsp_decoder_syslog());
}

sinsp_protodecoder_list::~sinsp_protodecoder_list()
{
	uint32_t j;

	for(j = 0; j < m_decoders_list.size(); j++)
	{
		delete m_decoders_list[j];
	}
}

void sinsp_protodecoder_list::add_protodecoder(sinsp_protodecoder* protodecoder)
{
	m_decoders_list.push_back(protodecoder);
}

sinsp_protodecoder* sinsp_protodecoder_list::new_protodecoder_from_name(const string& name,
																		   sinsp* inspector)
{
	uint32_t j;

	for(j = 0; j < m_decoders_list.size(); j++)
	{
		m_decoders_list[j]->m_inspector = inspector;

		if(m_decoders_list[j]->m_name == name)
		{
			sinsp_protodecoder* newchk = m_decoders_list[j]->allocate_new();
			newchk->set_inspector(inspector);
			return newchk;
		}
	}

	throw sinsp_exception("unknown protocol decoder " + name);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_decoder_syslog implementation
///////////////////////////////////////////////////////////////////////////////
const char* syslog_severity_strings[] =
{
	"emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"
};

const char* syslog_facility_strings[] =
{
	"kern", 
	"user", 
	"mail", 
	"daemon", 
	"auth", 
	"syslog", 
	"lpr", 
	"news", 
	"uucp", 
	"clock", 
	"authpriv", 
	"ftp", 
	"ntp", 
	"logaudit", 
	"logalert", 
	"cron",
	"local0",
	"local1",
	"local2",
	"local3",
	"local4",
	"local5",
	"local6",
	"local7"
};

sinsp_decoder_syslog::sinsp_decoder_syslog()
{
	m_name = "syslog";
	m_priority = -1;
}

sinsp_protodecoder* sinsp_decoder_syslog::allocate_new()
{
	return (sinsp_protodecoder*) new sinsp_decoder_syslog();
}

void sinsp_decoder_syslog::init()
{
	register_event_callback(CT_OPEN);
	register_event_callback(CT_CONNECT);
}

void sinsp_decoder_syslog::on_fd_from_proc(sinsp_fdinfo_t* fdinfo)
{
	if(fdinfo == NULL)
	{
		ASSERT(false);
		return ;
	}

	if(fdinfo->m_name.find("/dev/log") != string::npos)
	{
		register_write_callback(fdinfo);
	}
}

void sinsp_decoder_syslog::on_event(sinsp_evt* evt, sinsp_pd_callback_type etype)
{
	if(etype == CT_OPEN ||
		etype == CT_CONNECT)
	{
		sinsp_fdinfo_t* fdinfo = evt->get_fd_info();
		if(fdinfo == NULL)
		{
			return ;
		}

		if(fdinfo->m_name.find("/dev/log") != string::npos)
		{
			register_write_callback(fdinfo);
		}
	}
	else if(etype == CT_TUPLE_CHANGE)
	{
		sinsp_fdinfo_t* fdinfo = evt->get_fd_info();
		if(fdinfo == NULL)
		{
			return ;
		}

		if(fdinfo->m_name.find("/dev/log") != string::npos)
		{
			register_write_callback(fdinfo);
		}
		else
		{
			if(fdinfo->has_decoder_callbacks())
			{
				unregister_write_callback(fdinfo);
			}
		}
	}
	else
	{
		ASSERT(false);
	}
}

#define PRI_BUF_SIZE 16

void sinsp_decoder_syslog::on_write(sinsp_evt* evt, char *data, uint32_t len)
{
	char pri[PRI_BUF_SIZE];
	char* tc = data + 1;
	char* te = data + len;
	uint32_t j = 0;

	while(tc < te && *tc != '>' && *tc != '\0' && j < PRI_BUF_SIZE - 1)
	{
		pri[j++] = *tc;
		tc++;
	}

	pri[j] = 0;

	decode_message(data, len, pri, j);
}

void sinsp_decoder_syslog::on_reset(sinsp_evt* evt)
{
	m_priority = -1;
}

bool sinsp_decoder_syslog::is_data_valid()
{
	return (m_priority != -1);
}

const char* sinsp_decoder_syslog::get_severity_str()
{
	if(m_severity >= sizeof(syslog_severity_strings) / sizeof(syslog_severity_strings[0]))
	{
		return "<NA>";
	}
	else
	{
		return syslog_severity_strings[m_severity];
	}
}

const char* sinsp_decoder_syslog::get_facility_str()
{
	if(m_facility >= sizeof(syslog_facility_strings) / sizeof(syslog_facility_strings[0]))
	{
		return "<NA>";
	}
	else
	{
		return syslog_facility_strings[m_facility];
	}
}

void sinsp_decoder_syslog::decode_message(char *data, uint32_t len, char* pristr, uint32_t pristrlen)
{
	if(len < pristrlen + 2 || pristrlen == 0)
	{
		m_priority = -1;
		return;
	}

	bool res = sinsp_numparser::tryparsed32_fast(pristr, pristrlen, &m_priority);

	if(!res)
	{
		m_priority = -1;
		return;
	}

	m_severity = m_priority & 0x07;
	m_facility = m_priority >> 3;

	m_msg.assign(data + pristrlen + 2, len - pristrlen - 2);

	m_inspector->protodecoder_register_reset(this);
}

bool sinsp_decoder_syslog::get_info_line(char** res)
{
	m_infostr = string("syslog sev=") + get_severity_str() + " msg=" + m_msg;

	*res = (char*)m_infostr.c_str();
	return (m_priority != -1);
}
