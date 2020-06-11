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

#include <algorithm>
#ifndef _WIN32
#include <curses.h>
#endif

#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"
#include "filter.h"
#include "filterchecks.h"
#include "table.h"

extern sinsp_filter_check_list g_filterlist;
extern sinsp_evttables g_infotables;

//
//
// Table sorter functor
typedef struct table_row_cmp
{
	bool operator()(const sinsp_sample_row& src, const sinsp_sample_row& dst)
	{
		cmpop op;

		if(m_ascending)
		{
			op = CO_LT;
		}
		else
		{
			op = CO_GT;
		}

		if(src.m_values[m_colid].m_cnt > 1 ||
			dst.m_values[m_colid].m_cnt > 1)
		{
			return flt_compare_avg(op, m_type, 
				src.m_values[m_colid].m_val, 
				dst.m_values[m_colid].m_val, 
				src.m_values[m_colid].m_len, 
				dst.m_values[m_colid].m_len,
				src.m_values[m_colid].m_cnt, 
				dst.m_values[m_colid].m_cnt);
		}
		else
		{
			return flt_compare(op, m_type, 
				src.m_values[m_colid].m_val, 
				dst.m_values[m_colid].m_val, 
				src.m_values[m_colid].m_len, 
				dst.m_values[m_colid].m_len);
		}
	}

	uint32_t m_colid;
	ppm_param_type m_type;
	bool m_ascending;
}table_row_cmp;

sinsp_table::sinsp_table(sinsp* inspector, tabletype type, uint64_t refresh_interval_ns, 
	sinsp_table::output_type output_type, uint32_t json_first_row, uint32_t json_last_row)
{
	m_inspector = inspector;
	m_type = type;
	m_is_key_present = false;
	m_is_groupby_key_present = false;
	m_fld_pointers = NULL;
	m_premerge_fld_pointers = NULL;
	m_postmerge_fld_pointers = NULL;
	m_n_fields = 0;
	m_n_premerge_fields = 0;
	m_n_postmerge_fields = 0;
	m_refresh_interval_ns = refresh_interval_ns;
	m_output_type = output_type;
	m_next_flush_time_ns = 0;
	m_prev_flush_time_ns = 0;
	m_printer = new sinsp_filter_check_reference();
	m_buffer = &m_buffer1;
	m_is_sorting_ascending = false;
	m_sorting_col = -1;
	m_just_sorted = true;
	m_do_merging = true;
	m_types = &m_premerge_types;
	m_table = &m_premerge_table;
	m_extractors = &m_premerge_extractors;
	m_filter = NULL;
	m_use_defaults = false;
	m_zero_u64 = 0;
	m_zero_double = 0;
	m_paused = false;
	m_sample_data = NULL;
	m_json_first_row = json_first_row;
	m_json_last_row = json_last_row;
}

sinsp_table::~sinsp_table()
{
	uint32_t j;

	for(j = 0; j < m_chks_to_free.size(); j++)
	{
		delete m_chks_to_free[j];
	}

	if(m_premerge_fld_pointers != NULL)
	{
		delete[] m_premerge_fld_pointers;
	}

	if(m_postmerge_fld_pointers != NULL)
	{
		delete[] m_postmerge_fld_pointers;
	}

	if(m_filter != NULL)
	{
		delete m_filter;
	}
	
	delete m_printer;
}

void sinsp_table::configure(vector<sinsp_view_column_info>* entries, const string& filter, 
	bool use_defaults, uint32_t view_depth)
{
	m_use_defaults = use_defaults;
	m_view_depth = view_depth;

	//
	// If this is a list table, increase the refresh time to improve realtimyiness
	//
	if(m_type == sinsp_table::TT_LIST)
	{
		set_refresh_interval(200000000);
	}

	//////////////////////////////////////////////////////////////////////////////////////
	// If a filter has been specified, compile it
	//////////////////////////////////////////////////////////////////////////////////////
	if(filter != "")
	{
		sinsp_filter_compiler compiler(m_inspector, filter);
		m_filter = compiler.compile();
	}

	//////////////////////////////////////////////////////////////////////////////////////
	// Extract the tokens
	//////////////////////////////////////////////////////////////////////////////////////
	m_premerge_extractors.clear();

	for(auto vit : *entries)
	{
		sinsp_filter_check* chk = g_filterlist.new_filter_check_from_fldname(vit.get_field(m_view_depth), 
			m_inspector,
			false);

		if(chk == NULL)
		{
			throw sinsp_exception("invalid field name " + vit.get_field(m_view_depth));
		}

		chk->m_aggregation = (sinsp_field_aggregation)vit.m_aggregation;
		m_chks_to_free.push_back(chk);

		chk->parse_field_name(vit.get_field(m_view_depth).c_str(), true, false);

		if((vit.m_flags & TEF_IS_KEY) != 0)
		{
			if(m_is_key_present)
			{
				throw sinsp_exception("invalid table configuration: multiple keys specified");
			}

			m_premerge_extractors.insert(m_premerge_extractors.begin(), chk);
			m_is_key_present = true;
		}
		else
		{
			m_premerge_extractors.push_back(chk);
		}
	}

	if(m_type == sinsp_table::TT_TABLE)
	{
		//
		// Make sure this is a valid table
		//
		if(!m_is_key_present)
		{
			throw sinsp_exception("table is missing the key");
		}
	}
	else
	{
		sinsp_filter_check* chk = g_filterlist.new_filter_check_from_fldname("util.cnt", 
			m_inspector,
			false);

		if(chk == NULL)
		{
			throw sinsp_exception("internal table error");
		}

		chk->m_aggregation = A_NONE;
		m_chks_to_free.push_back(chk);

		chk->parse_field_name("util.cnt", true, false);

		if(m_is_key_present)
		{
			throw sinsp_exception("list table can't have a key");
		}

		m_premerge_extractors.insert(m_premerge_extractors.begin(), chk);
		m_is_key_present = true;
	}

	m_premerge_fld_pointers = new sinsp_table_field[m_premerge_extractors.size()];
	m_fld_pointers = m_premerge_fld_pointers;
	m_n_premerge_fields = (uint32_t)m_premerge_extractors.size();
	m_n_fields = m_n_premerge_fields;

	if(m_n_fields < 2)
	{
		throw sinsp_exception("table has no values");
	}

	for(auto it = m_premerge_extractors.begin(); it != m_premerge_extractors.end(); ++it)
	{
		m_premerge_types.push_back((*it)->get_field_info()->m_type);
		m_premerge_legend.push_back(*(*it)->get_field_info());
	}

	m_premerge_vals_array_sz = (m_n_fields - 1) * sizeof(sinsp_table_field);
	m_vals_array_sz = m_premerge_vals_array_sz;

	//////////////////////////////////////////////////////////////////////////////////////
	// If a merge has been specified, configure it 
	//////////////////////////////////////////////////////////////////////////////////////
	uint32_t n_gby_keys = 0;

	for(auto vit : *entries)
	{
		if((vit.m_flags & TEF_IS_GROUPBY_KEY) != 0)
		{
			n_gby_keys++;
		}
	}

	if(n_gby_keys == 0)
	{
		//
		// No merge string. We can stop here
		//
		m_do_merging = false;
		return;
	}
	else if(n_gby_keys > 1)
	{
		throw sinsp_exception("invalid table definition: multiple groupby keys");
	}

	//
	// Merging not supported for lists
	//
	if(m_type != sinsp_table::TT_TABLE)
	{
		throw sinsp_exception("group by not supported for list tables");
	}

	m_do_merging = true;

	for(uint32_t j = 0; j < entries->size(); j++)
	{
		auto vit = entries->at(j);

		//
		// Skip original key when grouping
		//
		if((vit.m_flags & TEF_IS_KEY) != 0)
		{
			continue;
		}


		sinsp_filter_check* chk = m_premerge_extractors[j];

		chk->m_merge_aggregation = (sinsp_field_aggregation)vit.m_groupby_aggregation;

		if((vit.m_flags & TEF_IS_GROUPBY_KEY) != 0)
		{
			if(m_is_groupby_key_present)
			{
				throw sinsp_exception("invalid table configuration: more than one groupby key specified");
			}

			m_is_groupby_key_present = true;
			m_postmerge_extractors.insert(m_postmerge_extractors.begin(), chk);
			m_groupby_columns.insert(m_groupby_columns.begin(), j);
		}
		else
		{
			m_postmerge_extractors.push_back(chk);
			m_groupby_columns.push_back(j);
		}
	}

	m_postmerge_fld_pointers = new sinsp_table_field[m_postmerge_extractors.size()];
	m_n_postmerge_fields = (uint32_t)m_postmerge_extractors.size();

	if(!m_is_groupby_key_present)
	{
		throw sinsp_exception("table is missing the groupby key");
	}

	if(m_groupby_columns.size() < 2)
	{
		throw sinsp_exception("groupby table has no values");
	}

	for(auto it = m_postmerge_extractors.begin(); it != m_postmerge_extractors.end(); ++it)
	{
		m_postmerge_types.push_back((*it)->get_field_info()->m_type);
		m_postmerge_legend.push_back(*(*it)->get_field_info());
	}

	m_postmerge_vals_array_sz = (m_n_postmerge_fields - 1) * sizeof(sinsp_table_field);
}

void sinsp_table::add_row(bool merging)
{
	uint32_t j;

	sinsp_table_field key(m_fld_pointers[0].m_val, 
		m_fld_pointers[0].m_len,
		m_fld_pointers[0].m_cnt);

	if(m_type == sinsp_table::TT_TABLE)
	{
		//
		// This is a table. Do a proper key lookup and update the entry
		//
		auto it = m_table->find(key);

		if(it == m_table->end())
		{
			//
			// New entry
			//
			key.m_val = key.m_val;
			key.m_cnt = 1;
			m_vals = (sinsp_table_field*)m_buffer->reserve(m_vals_array_sz);

			for(j = 1; j < m_n_fields; j++)
			{
				uint32_t vlen = get_field_len(j);
				m_vals[j - 1].m_val = m_fld_pointers[j].m_val;
				m_vals[j - 1].m_len = vlen;
				m_vals[j - 1].m_cnt = m_fld_pointers[j].m_cnt;
			}

			(*m_table)[key] = m_vals;
		}
		else
		{
			//
			// Existing entry
			//
			m_vals = it->second;

			for(j = 1; j < m_n_fields; j++)
			{
				if(merging)
				{
					add_fields(j, &m_fld_pointers[j], m_postmerge_extractors[j]->m_merge_aggregation);
				}
				else
				{
					add_fields(j, &m_fld_pointers[j], m_premerge_extractors[j]->m_aggregation);
				}
			}
		}
	}
	else
	{
		//
		// We are in list mode. Just append the row to the end of the sample
		//
		if(m_paused)
		{
			return;
		}

		sinsp_sample_row row;

		//
		// This is a list. Create the new entry and push it back.
		//
		key.m_val = key.m_val;
		key.m_cnt = 1;
		row.m_key = key;

		m_vals = (sinsp_table_field*)m_buffer->reserve(m_vals_array_sz);

		for(j = 1; j < m_n_fields; j++)
		{
			uint32_t vlen = get_field_len(j);
			m_vals[j - 1].m_val = m_fld_pointers[j].m_val;
			m_vals[j - 1].m_len = vlen;
			m_vals[j - 1].m_cnt = 1;
			row.m_values.push_back(m_vals[j - 1]);
		}

		m_full_sample_data.push_back(row);
	}
}

void sinsp_table::process_event(sinsp_evt* evt)
{
	uint32_t j;

	//
	// Apply the filter
	//
	if(m_filter)
	{
		if(!m_filter->run(evt))
		{
			return;
		}
	}

	//
	// Extract the values and create the row to add
	//
	for(j = 0; j < m_n_premerge_fields; j++)
	{
		uint32_t len;
		uint8_t* val = m_premerge_extractors[j]->extract(evt, &len);

		sinsp_table_field* pfld = &(m_premerge_fld_pointers[j]);

		//
		// XXX For the moment, we only support defaults for numeric fields.
		// At a certain point we will want to introduce the concept of zero
		// for other fields too.
		//
		if(val == NULL)
		{
			if(m_use_defaults)
			{
				pfld->m_val = get_default_val(&m_premerge_legend[j]);
				if(pfld->m_val == NULL)
				{
					return;
				}

				pfld->m_len = get_field_len(j);
				pfld->m_val = m_buffer->copy(pfld->m_val, pfld->m_len);
				pfld->m_cnt = 0;
			}
			else
			{
				return;
			}
		}
		else
		{
			pfld->m_val = val;
			pfld->m_len = get_field_len(j);
			pfld->m_val = m_buffer->copy(val, pfld->m_len);
			pfld->m_cnt = 1;
		}
	}

	//
	// Add the row
	//
	add_row(false);

	return;
}

void sinsp_table::process_proctable(sinsp_evt* evt)
{
	sinsp_evt tevt;
	scap_evt tscapevt;

	threadinfo_map_t* threadtable  = m_inspector->m_thread_manager->get_threads();
	ASSERT(threadtable != NULL);

	uint64_t ts = evt->get_ts();
	uint64_t ts_s = ts - (ts % ONE_SECOND_IN_NS);
	tscapevt.ts = ts_s - 1;

	//
	// Note: as the event type for this fake event, we pick one of the unused
	//       numbers, so we guarantee that filter checks will not wrongly pick it up
	//
	tscapevt.type = PPME_SYSDIGEVENT_X;
	tscapevt.len = 0;
	tscapevt.nparams = 0;

	tevt.m_inspector = m_inspector;
	tevt.m_info = &(g_infotables.m_event_info[PPME_SYSDIGEVENT_X]);
	tevt.m_pevt = NULL;
	tevt.m_cpuid = 0;
	tevt.m_evtnum = 0;
	tevt.m_pevt = &tscapevt;
	tevt.m_fdinfo = NULL;

	threadtable->loop([&] (sinsp_threadinfo& tinfo) {
		tevt.m_tinfo = &tinfo;
		tscapevt.tid = tevt.m_tinfo->m_tid;

		if(m_filter)
		{
			if(!m_filter->run(&tevt))
			{
				return true;
			}
		}

		process_event(&tevt);
		return true;
	});
}

void sinsp_table::flush(sinsp_evt* evt)
{	
	if(!m_paused)
	{
		if(m_next_flush_time_ns != 0)
		{
			//
			// Time to emit the sample! 
			// Add the proctable as a sample at the end of the second
			//
			process_proctable(evt);

			//
			// If there is a merging step, switch the types to point to the merging ones.
			//
			if(m_do_merging)
			{
				m_types = &m_postmerge_types;
				m_table = &m_merge_table;
				m_n_fields = m_n_postmerge_fields;
				m_vals_array_sz = m_postmerge_vals_array_sz;
				m_fld_pointers = m_postmerge_fld_pointers;
				m_extractors = &m_postmerge_extractors;
			}

			//
			// Emit the sample
			//
			create_sample();

			if(m_type == sinsp_table::TT_TABLE)
			{
				//
				// Switch the data storage so that the current one is still usable by the 
				// consumers of the table.
				//
				switch_buffers();

				//
				// Clear the current data storage
				//
				m_buffer->clear();
			}

			//
			// Reinitialize the tables
			//
			m_premerge_table.clear();
			m_merge_table.clear();
		}
	}

	uint64_t ts = evt->get_ts();

	m_prev_flush_time_ns = m_next_flush_time_ns;
	m_next_flush_time_ns = ts - (ts % m_refresh_interval_ns) + m_refresh_interval_ns;

	return;
}

void sinsp_table::print_raw(vector<sinsp_sample_row>* sample_data, uint64_t time_delta)
{
	vector<filtercheck_field_info>* legend = get_legend();

	for(auto it = sample_data->begin(); it != sample_data->end(); ++it)
	{
		for(uint32_t j = 0; j < m_n_fields - 1; j++)
		{
			sinsp_filter_check* extractor = m_extractors->at(j + 1);
			uint64_t td = 0;

			if(extractor->m_aggregation == A_TIME_AVG || 
				extractor->m_merge_aggregation == A_TIME_AVG)
			{
				td = time_delta;
			}

			m_printer->set_val(m_types->at(j + 1), 
				it->m_values[j].m_val,
				it->m_values[j].m_len,
				it->m_values[j].m_cnt,
				legend->at(j + 1).m_print_format);
			char* prstr = m_printer->tostring_nice(NULL, 10, td);
			printf("%s ", prstr);
			//printf("%s ", m_printer->tostring(NULL));
		}

		printf("\n");
	}

	printf("----------------------\n");
}

void sinsp_table::print_json(vector<sinsp_sample_row>* sample_data, uint64_t time_delta)
{
	Json::FastWriter writer;
	vector<filtercheck_field_info>* legend = get_legend();
	string res;
	uint32_t j = 0;
	uint32_t k = 0;
	m_json_output_lines_count = 0;

	if(sample_data->size() == 0)
	{
		return;
	}

	if(m_json_first_row >= sample_data->size())
	{
		return;
	}

	if(m_json_last_row == 0 || m_json_last_row >= sample_data->size() - 1)
	{
		m_json_last_row = sample_data->size() - 1;
	}

	printf("\"data\": [\n");

	for(k = m_json_first_row; k <= m_json_last_row; k++)
	{
		Json::Value root;
		Json::Value jd;
		auto row = sample_data->at(k);
		
		for(uint32_t j = 0; j < m_n_fields - 1; j++)
		{
			sinsp_filter_check* extractor = m_extractors->at(j + 1);
			uint64_t td = 0;

			if(extractor->m_aggregation == A_TIME_AVG || 
				extractor->m_merge_aggregation == A_TIME_AVG)
			{
				td = time_delta;
			}

			m_printer->set_val(m_types->at(j + 1), 
				row.m_values[j].m_val,
				row.m_values[j].m_len,
				row.m_values[j].m_cnt,
				legend->at(j + 1).m_print_format);

			jd.append(m_printer->tojson(NULL, 10, td));
		}


		auto key = get_row_key_name_and_val(k, false);

		root["k"] = key.second;
		root["d"] = jd;

		res = writer.write(root);
		printf("%s", res.substr(0, res.size() - 1).c_str());

		m_json_output_lines_count++;

		if(k >= m_json_last_row)
		{
			break;
		}

		if(j < sample_data->size() - 1)
		{
			printf(",");
		}
		printf("\n");

		j++;
	}

	printf("],\n");
}

void sinsp_table::filter_sample()
{
	vector<filtercheck_field_info>* legend = get_legend();

	m_filtered_sample_data.clear();

	for(auto it : m_full_sample_data)
	{
		for(uint32_t j = 0; j < it.m_values.size(); j++)
		{
			ppm_param_type type;

			if(m_do_merging)
			{
				type = m_postmerge_types[j + 1];
			}
			else
			{
				type = m_premerge_types[j + 1];
			}

			if(type == PT_CHARBUF || type == PT_BYTEBUF || type == PT_SYSCALLID ||
				type == PT_PORT || type == PT_L4PROTO || type == PT_SOCKFAMILY || type == PT_IPV4ADDR ||
			        type == PT_IPV6ADDR ||
				type == PT_UID || type == PT_GID)
			{
				m_printer->set_val(type, 
					it.m_values[j].m_val, 
					it.m_values[j].m_len,
					it.m_values[j].m_cnt,
					legend->at(j + 1).m_print_format);
					
				string strval = m_printer->tostring_nice(NULL, 0, 0);

				if(strval.find(m_freetext_filter) != string::npos)
				{
					m_filtered_sample_data.push_back(it);
					break;
				}
			}
		}
	}
}

//
// Returns the key of the first match, or NULL if no match
//
sinsp_table_field* sinsp_table::search_in_sample(string text)
{
	vector<filtercheck_field_info>* legend = get_legend();

	for(auto it = m_full_sample_data.begin(); it != m_full_sample_data.end(); ++it)
	{
		for(uint32_t j = 0; j < it->m_values.size(); j++)
		{
			ppm_param_type type;

			if(m_do_merging)
			{
				ASSERT(m_types->size() == it->m_values.size() + 2);
				type = m_types->at(j + 2);
			}
			else
			{
				ASSERT(m_types->size() == it->m_values.size() + 1);
				type = m_types->at(j + 1);
			}

			if(type == PT_CHARBUF || type == PT_BYTEBUF || type == PT_SYSCALLID ||
				type == PT_PORT || type == PT_L4PROTO || type == PT_SOCKFAMILY || type == PT_IPV4ADDR ||
			        type == PT_IPV6ADDR ||
				type == PT_UID || type == PT_GID)
			{
				m_printer->set_val(type,
					it->m_values[j].m_val,
					it->m_values[j].m_len,
					it->m_values[j].m_cnt,
					legend->at(j + 1).m_print_format);

				string strval = m_printer->tostring_nice(NULL, 0, 0);

				if(strval.find(text) != string::npos)
				{
					return &(it->m_key);
				}
			}
		}
	}

	return NULL;
}

void sinsp_table::sort_sample()
{
	if(m_type == sinsp_table::TT_LIST)
	{
		if(m_sorting_col == -1 || !m_just_sorted)
		{
			return;
		}

		m_just_sorted = false;
	}

	if(m_sample_data->size() != 0)
	{
		if(m_sorting_col >= (int32_t)m_sample_data->at(0).m_values.size())
		{
			throw sinsp_exception("invalid table sorting column");
		}

		table_row_cmp cc;
		cc.m_colid = m_sorting_col;
		cc.m_ascending = m_is_sorting_ascending;
		uint32_t tyid = m_do_merging? m_sorting_col + 2 : m_sorting_col + 1;
		cc.m_type = m_premerge_types[tyid];

		sort(m_sample_data->begin(),
			m_sample_data->end(),
			cc);
	}
}

vector<sinsp_sample_row>* sinsp_table::get_sample(uint64_t time_delta)
{
	//
	// No sample generation happens when the table is paused
	//
	if(!m_paused)
	{
		//
		// If we have a freetext filter, we start by filtering the sample
		//
		if(m_freetext_filter != "")
		{
			filter_sample();
			m_sample_data = &m_filtered_sample_data;
		}
		else
		{
			m_sample_data = &m_full_sample_data;
		}

		//
		// Sort the sample
		//
		sort_sample();
	}

	//
	// If required, emit the sample to stdout
	//
#ifndef _WIN32
	if(m_output_type != sinsp_table::OT_CURSES)
	{
#endif
		if(m_output_type == sinsp_table::OT_RAW)
		{
			print_raw(m_sample_data, time_delta);
		}
		else if(m_output_type == sinsp_table::OT_JSON)
		{
			print_json(m_sample_data, time_delta);
		}
		else
		{
			ASSERT(false);
		}
#ifndef _WIN32
	}
#endif

	//
	// Restore the lists used for event processing
	//
	m_types = &m_premerge_types;
	m_table = &m_premerge_table;
	m_n_fields = m_n_premerge_fields;
	m_vals_array_sz = m_premerge_vals_array_sz;
	m_fld_pointers = m_premerge_fld_pointers;
	m_extractors = &m_premerge_extractors;

	return m_sample_data;
}

void sinsp_table::set_sorting_col(uint32_t col)
{
	uint32_t n_fields;
	vector<ppm_param_type>* types;

	if(m_do_merging)
	{
		n_fields = m_n_postmerge_fields;
		types = &m_postmerge_types;
	}
	else
	{
		n_fields = m_n_premerge_fields;
		types = &m_premerge_types;
	}

	if(col == 0)
	{
		if(m_type == sinsp_table::TT_TABLE)
		{
			throw sinsp_exception("cannot sort by key");
		}
		else
		{
			m_sorting_col = -1;
			return;
		}
	}

	if(col >= n_fields)
	{
		throw sinsp_exception("invalid table sorting column");
	}

	if(col == (uint32_t)(m_sorting_col + 1))
	{
		m_is_sorting_ascending = !m_is_sorting_ascending;
	}
	else
	{
		switch(types->at(col))
		{
			case PT_INT8:
			case PT_INT16:
			case PT_INT32:
			case PT_INT64:
			case PT_UINT8:
			case PT_UINT16:
			case PT_UINT32:
			case PT_UINT64:
			case PT_RELTIME:
			case PT_ABSTIME:
			case PT_DOUBLE:
			case PT_BOOL:
				m_is_sorting_ascending = false;
				break;
			default:
				m_is_sorting_ascending = true;
				break;
		}
	}

	m_just_sorted = true;
	m_sorting_col = col - 1;
}

uint32_t sinsp_table::get_sorting_col()
{
	return (uint32_t)m_sorting_col + 1;
}

void sinsp_table::create_sample()
{
	if(m_type == sinsp_table::TT_TABLE)
	{
		uint32_t j;
		m_full_sample_data.clear();
		sinsp_sample_row row;

		//
		// If merging is on, perform the merge and switch to the merged table 
		//
		if(m_do_merging)
		{
			m_table = &m_merge_table;
			m_merge_table.clear();

			for(auto it = m_premerge_table.begin(); it != m_premerge_table.end(); ++it)
			{
				for(j = 0; j < m_n_postmerge_fields; j++)
				{
					sinsp_table_field* pfld = &(m_postmerge_fld_pointers[j]);

					uint32_t col = m_groupby_columns[j];
					if(col == 0)
					{
						pfld->m_val = it->first.m_val;
						pfld->m_len = it->first.m_len;
						pfld->m_cnt = it->first.m_cnt;
					}
					else
					{
						pfld->m_val = it->second[col - 1].m_val;
						pfld->m_len = it->second[col - 1].m_len;
						pfld->m_cnt = it->second[col - 1].m_cnt;
					}
				}

				add_row(true);
			}
		}
		else
		{
			m_table = &m_premerge_table;
		}

		//
		// Emit the table
		//
		for(auto it = m_table->begin(); it != m_table->end(); ++it)
		{
			row.m_key = it->first;

			row.m_values.clear();

			sinsp_table_field* fields = it->second;
			for(j = 0; j < m_n_fields - 1; j++)
			{
				row.m_values.push_back(fields[j]);
			}

			m_full_sample_data.push_back(row);
		}
	}
	else
	{
		//
		// If this is a list, there's nothing to be done, since m_full_sample_data
		// is already prepared and doesn't need to be cleaned.
		//
		return;
	}
}

void sinsp_table::add_fields_sum(ppm_param_type type, sinsp_table_field *dst, sinsp_table_field *src)
{
	uint8_t* operand1 = dst->m_val;
	uint8_t* operand2 = src->m_val;
	
	switch(type)
	{
	case PT_INT8:
		*(int8_t*)operand1 += *(int8_t*)operand2;
		return;
	case PT_INT16:
		*(int16_t*)operand1 += *(int16_t*)operand2;
		return;
	case PT_INT32:
		*(int32_t*)operand1 += *(int32_t*)operand2;
		return;
	case PT_INT64:
		*(int64_t*)operand1 += *(int64_t*)operand2;
		return;
	case PT_UINT8:
		*(uint8_t*)operand1 += *(uint8_t*)operand2;
		return;
	case PT_UINT16:
		*(uint16_t*)operand1 += *(uint16_t*)operand2;
		return;
	case PT_UINT32:
	case PT_BOOL:
		*(uint32_t*)operand1 += *(uint32_t*)operand2;
		return;
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		*(uint64_t*)operand1 += *(uint64_t*)operand2;
		return;
	case PT_DOUBLE:
		*(double*)operand1 += *(double*)operand2;
		return;
	default:
		return;
	}
}

void sinsp_table::add_fields_sum_of_avg(ppm_param_type type, sinsp_table_field *dst, sinsp_table_field *src)
{
	uint8_t* operand1 = dst->m_val;
	uint8_t* operand2 = src->m_val;
	uint32_t cnt1 = dst->m_cnt;
	uint32_t cnt2 = src->m_cnt;
	
	switch(type)
	{
	case PT_INT8:
		if(cnt1 > 1)
		{
			*(int8_t*)operand1 = *(int8_t*)operand1 / cnt1;
		}

		*(int8_t*)operand1 += (*(int8_t*)operand2) / cnt2;
		break;
	case PT_INT16:
		if(cnt1 > 1)
		{
			*(int16_t*)operand1 = *(int16_t*)operand1 / cnt1;
		}

		*(int16_t*)operand1 += (*(int16_t*)operand2) / cnt2;
		break;
	case PT_INT32:
		if(cnt1 > 1)
		{
			*(int32_t*)operand1 = *(int32_t*)operand1 / cnt1;
		}

		*(int32_t*)operand1 += (*(int32_t*)operand2) / cnt2;
		break;
	case PT_INT64:
		if(cnt1 > 1)
		{
			*(int64_t*)operand1 = *(int64_t*)operand1 / cnt1;
		}

		*(int64_t*)operand1 += (*(int64_t*)operand2) / cnt2;
		break;
	case PT_UINT8:
		if(cnt1 > 1)
		{
			*(uint8_t*)operand1 = *(uint8_t*)operand1 / cnt1;
		}

		*(uint8_t*)operand1 += (*(uint8_t*)operand2) / cnt2;
		break;
	case PT_UINT16:
		if(cnt1 > 1)
		{
			*(uint16_t*)operand1 = *(uint16_t*)operand1 / cnt1;
		}

		*(uint16_t*)operand1 += (*(uint16_t*)operand2) / cnt2;
		break;
	case PT_UINT32:
	case PT_BOOL:
		if(cnt1 > 1)
		{
			*(uint32_t*)operand1 = *(uint32_t*)operand1 / cnt1;
		}

		*(uint32_t*)operand1 += (*(uint32_t*)operand2) / cnt2;
		break;
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		if(cnt1 > 1)
		{
			*(uint64_t*)operand1 = *(uint64_t*)operand1 / cnt1;
		}

		*(uint64_t*)operand1 += (*(uint64_t*)operand2) / cnt2;
		break;
	case PT_DOUBLE:
		if(cnt1 > 1)
		{
			*(double*)operand1 = *(double*)operand1 / cnt1;
		}

		*(double*)operand1 += (*(double*)operand2) / cnt2;
		break;
	default:
		break;
	}

	src->m_cnt = 1;
	dst->m_cnt = 1;
}

void sinsp_table::add_fields_max(ppm_param_type type, sinsp_table_field *dst, sinsp_table_field *src)
{
	uint8_t* operand1 = dst->m_val;
	uint8_t* operand2 = src->m_val;

	switch(type)
	{
	case PT_INT8:
		if(*(int8_t*)operand1 < *(int8_t*)operand2)
		{
			*(int8_t*)operand1 = *(int8_t*)operand2;
		}
		return;
	case PT_INT16:
		if(*(int16_t*)operand1 < *(int16_t*)operand2)
		{
			*(int16_t*)operand1 = *(int16_t*)operand2;
		}
		return;
	case PT_INT32:
		if(*(int32_t*)operand1 < *(int32_t*)operand2)
		{
			*(int32_t*)operand1 = *(int32_t*)operand2;
		}
		return;
	case PT_INT64:
		if(*(int64_t*)operand1 < *(int64_t*)operand2)
		{
			*(int64_t*)operand1 = *(int64_t*)operand2;
		}
		return;
	case PT_UINT8:
		if(*(uint8_t*)operand1 < *(uint8_t*)operand2)
		{
			*(uint8_t*)operand1 = *(uint8_t*)operand2;
		}
		return;
	case PT_UINT16:
		if(*(uint16_t*)operand1 < *(uint16_t*)operand2)
		{
			*(uint16_t*)operand1 = *(uint16_t*)operand2;
		}
		return;
	case PT_UINT32:
	case PT_BOOL:
		if(*(uint32_t*)operand1 < *(uint32_t*)operand2)
		{
			*(uint32_t*)operand1 = *(uint32_t*)operand2;
		}
		return;
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		if(*(uint64_t*)operand1 < *(uint64_t*)operand2)
		{
			*(uint64_t*)operand1 = *(uint64_t*)operand2;
		}
		return;
	case PT_DOUBLE:
		if(*(double*)operand1 < *(double*)operand2)
		{
			*(double*)operand1 = *(double*)operand2;
		}
		return;
	case PT_CHARBUF:
	case PT_BYTEBUF:
		if(dst->m_len >= src->m_len)
		{
			memcpy(dst->m_val, src->m_val, src->m_len);
		}
		else
		{
			dst->m_val = m_buffer->copy(src->m_val, src->m_len);
		}

		dst->m_len = src->m_len;
	default:
		return;
	}
}

void sinsp_table::add_fields_min(ppm_param_type type, sinsp_table_field *dst, sinsp_table_field *src)
{
	uint8_t* operand1 = dst->m_val;
	uint8_t* operand2 = src->m_val;

	switch(type)
	{
	case PT_INT8:
		if(*(int8_t*)operand1 > *(int8_t*)operand2)
		{
			*(int8_t*)operand1 = *(int8_t*)operand2;
		}
		return;
	case PT_INT16:
		if(*(int16_t*)operand1 > *(int16_t*)operand2)
		{
			*(int16_t*)operand1 = *(int16_t*)operand2;
		}
		return;
	case PT_INT32:
		if(*(int32_t*)operand1 > *(int32_t*)operand2)
		{
			*(int32_t*)operand1 = *(int32_t*)operand2;
		}
		return;
	case PT_INT64:
		if(*(int64_t*)operand1 > *(int64_t*)operand2)
		{
			*(int64_t*)operand1 = *(int64_t*)operand2;
		}
		return;
	case PT_UINT8:
		if(*(uint8_t*)operand1 > *(uint8_t*)operand2)
		{
			*(uint8_t*)operand1 = *(uint8_t*)operand2;
		}
		return;
	case PT_UINT16:
		if(*(uint16_t*)operand1 > *(uint16_t*)operand2)
		{
			*(uint16_t*)operand1 = *(uint16_t*)operand2;
		}
		return;
	case PT_UINT32:
	case PT_BOOL:
		if(*(uint32_t*)operand1 > *(uint32_t*)operand2)
		{
			*(uint32_t*)operand1 = *(uint32_t*)operand2;
		}
		return;
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		if(*(uint64_t*)operand1 > *(uint64_t*)operand2)
		{
			*(uint64_t*)operand1 = *(uint64_t*)operand2;
		}
		return;
	case PT_DOUBLE:
		if(*(double*)operand1 > *(double*)operand2)
		{
			*(double*)operand1 = *(double*)operand2;
		}
		return;
	case PT_CHARBUF:
	case PT_BYTEBUF:
		ASSERT(false); // Not supposed to use this
		if(dst->m_len >= src->m_len)
		{
			memcpy(dst->m_val, src->m_val, src->m_len);
		}
		else
		{
			dst->m_val = m_buffer->copy(src->m_val, src->m_len);
		}

		dst->m_len = src->m_len;
	default:
		return;
	}
}

void sinsp_table::add_fields(uint32_t dst_id, sinsp_table_field* src, uint32_t aggr)
{
	ppm_param_type type = (*m_types)[dst_id];
	sinsp_table_field* dst = &(m_vals[dst_id - 1]);

	switch(aggr)
	{
	case A_NONE:
		return;
	case A_SUM:
	case A_TIME_AVG:
		if(src->m_cnt < 2)
		{
			add_fields_sum(type, dst, src);
		}
		else
		{
			add_fields_sum_of_avg(type, dst, src);
		}

		return;
	case A_AVG:
		dst->m_cnt += src->m_cnt;
		add_fields_sum(type, dst, src);		
		return;
	case A_MAX:
		add_fields_max(type, dst, src);		
		return;
	case A_MIN:
		if(src->m_cnt != 0)
		{
			if(dst->m_cnt == 0)
			{
				add_fields_sum(type, dst, src);
				dst->m_cnt++;
			}
			else
			{
				add_fields_min(type, dst, src);
			}
		}
		return;
	default:
		ASSERT(false);
		return;
	}
}

uint32_t sinsp_table::get_field_len(uint32_t id)
{
	ppm_param_type type;
	sinsp_table_field *fld;

	type = (*m_types)[id];
	fld = &(m_fld_pointers[id]);

	switch(type)
	{
	case PT_INT8:
		return 1;
	case PT_INT16:
		return 2;
	case PT_INT32:
		return 4;
	case PT_INT64:
	case PT_FD:
	case PT_PID:
	case PT_ERRNO:
		return 8;
	case PT_FLAGS8:
	case PT_UINT8:
	case PT_SIGTYPE:
		return 1;
	case PT_FLAGS16:
	case PT_UINT16:
	case PT_PORT:
	case PT_SYSCALLID:
		return 2;
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_MODE:
	case PT_BOOL:
	case PT_IPV4ADDR:
	case PT_SIGSET:
		return 4;
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		return 8;
	case PT_CHARBUF:
		return (uint32_t)(strlen((char*)fld->m_val) + 1);
	case PT_BYTEBUF:
		return fld->m_len;
	case PT_DOUBLE:
		return sizeof(double);
	case PT_IPV6ADDR:
		return sizeof(ipv6addr);
	case PT_IPADDR:
	case PT_IPNET:
		if(fld->m_len == sizeof(struct in_addr))
		{
			return 4;
		}
		else
		{
			return sizeof(ipv6addr);
		}
	case PT_SOCKADDR:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	case PT_FSPATH:
	default:
		ASSERT(false);
		return false;
	}
}

uint8_t* sinsp_table::get_default_val(filtercheck_field_info* fld)
{
	switch(fld->m_type)
	{
	case PT_INT8:
	case PT_INT16:
	case PT_INT32:
	case PT_INT64:
	case PT_UINT8:
	case PT_UINT16:
	case PT_UINT32:
	case PT_UINT64:
	case PT_BOOL:
	case PT_RELTIME:
	case PT_ABSTIME:
		if(fld->m_print_format == PF_DEC)
		{
			return (uint8_t*)&m_zero_u64;
		}
		else
		{
			return NULL;
		}
	case PT_DOUBLE:
			return (uint8_t*)&m_zero_double;
	case PT_CHARBUF:
			return (uint8_t*)&m_zero_u64;
	case PT_PORT:
	case PT_IPV4ADDR:
	case PT_IPV6ADDR:
		return NULL;
	default:
		ASSERT(false);
		return NULL;
	}
}

void sinsp_table::switch_buffers()
{
	if(m_buffer == &m_buffer1)
	{
		m_buffer = &m_buffer2;
	}
	else
	{
		m_buffer = &m_buffer1;
	}
}

pair<filtercheck_field_info*, string> sinsp_table::get_row_key_name_and_val(uint32_t rownum, bool force)
{
	pair<filtercheck_field_info*, string> res;
	vector<sinsp_filter_check*>* extractors;
	vector<ppm_param_type>* types;

	if(m_do_merging)
	{
		extractors = &m_postmerge_extractors;
		types = &m_postmerge_types;
	}
	else
	{
		extractors = &m_premerge_extractors;
		types = &m_premerge_types;
	}

	if(m_sample_data == NULL || rownum >= m_sample_data->size())
	{
		ASSERT(m_sample_data == NULL || m_sample_data->size() == 0);
		if(force)
		{
			res.first = (filtercheck_field_info*)((*extractors)[0])->get_field_info();
			ASSERT(res.first != NULL);
		}
		else
		{
			res.first = NULL;
		}
		res.second = "";
	}
	else
	{
		vector<filtercheck_field_info>* legend = get_legend();
		res.first = (filtercheck_field_info*)((*extractors)[0])->get_field_info();
		ASSERT(res.first != NULL);

		m_printer->set_val(types->at(0),
			m_sample_data->at(rownum).m_key.m_val, 
			m_sample_data->at(rownum).m_key.m_len,
			m_sample_data->at(rownum).m_key.m_cnt,
			legend->at(0).m_print_format);

		res.second = m_printer->tostring(NULL);
	}

	return res;
}

sinsp_table_field* sinsp_table::get_row_key(uint32_t rownum)
{
	if(rownum >= m_sample_data->size())
	{
		return NULL;
	}

	return &m_sample_data->at(rownum).m_key;
}

int32_t sinsp_table::get_row_from_key(sinsp_table_field* key)
{
	uint32_t j;

	for(j = 0; j < m_sample_data->size(); j++)
	{
		sinsp_table_field* rowkey = &(m_sample_data->at(j).m_key);

		if(rowkey->m_len == key->m_len)
		{
			if(memcmp(rowkey->m_val, key->m_val, key->m_len) == 0)
			{
				return j;
			}
		}
	}

	return -1;
}

void sinsp_table::set_paused(bool paused)
{
	m_paused = paused;
}

void sinsp_table::clear()
{
	if(m_type == sinsp_table::TT_LIST)
	{
		m_full_sample_data.clear();
		m_buffer->clear();
	}
	else
	{
		ASSERT(false);
	}
}
