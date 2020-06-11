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

#define SINSP_TABLE_DEFAULT_REFRESH_INTERVAL_NS 1000000000
#define SINSP_TABLE_BUFFER_ENTRY_SIZE 16384

class sinsp_filter_check_reference;

typedef enum sysdig_table_action
{
	STA_NONE,
	STA_PARENT_HANDLE,
	STA_QUIT,
	STA_SWITCH_VIEW,
	STA_SWITCH_SPY,
	STA_DRILLDOWN,
	STA_DRILLDOWN_TEMPLATE,
	STA_DRILLUP,
	STA_SPY,
	STA_DIG,
	STA_SPECTRO,
	STA_SPECTRO_FILE,
	STA_DESTROY_CHILD,
}sysdig_table_action;

class sinsp_table_field
{
public:
	sinsp_table_field()
	{
		m_val = NULL;
	}

	sinsp_table_field(uint8_t* val, uint32_t len, uint32_t cnt)
	{
		m_len = len;
		m_val = val;
		m_cnt = cnt;
	}

	bool operator==(const sinsp_table_field &other) const
	{
		if(m_len!= other.m_len)
		{
			return false;
		}

		if(memcmp(m_val, other.m_val, m_len) == 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	uint32_t m_len;
	uint32_t m_cnt;		// For averages, this stores the entry count
	uint8_t* m_val;

	friend class curses_table;	
};

#define STF_STORAGE_BUFSIZE 512

class sinsp_table_field_storage : public sinsp_table_field
{
public:
	sinsp_table_field_storage()
	{
		m_storage_len = STF_STORAGE_BUFSIZE;
		m_val = new uint8_t[m_storage_len];
		m_isvalid = false;
	}

	~sinsp_table_field_storage()
	{
		if(m_val != NULL)
		{
			delete[] m_val;
		}
	}

	void copy(sinsp_table_field* other)
	{
		if(other->m_len > m_storage_len)
		{
			resize(other->m_len);
		}

		m_len = other->m_len;

		memcpy(m_val, other->m_val, m_len);
	}

	bool m_isvalid;

private:
	void resize(uint32_t newlen)
	{
		delete[] m_val;
		m_val = NULL;
		m_storage_len = newlen;
		m_val = new uint8_t[m_storage_len];
	}

	uint32_t m_storage_len;
};

struct sinsp_table_field_hasher
{
  size_t operator()(const sinsp_table_field& k) const
  {
	  size_t h = 0;
	  uint8_t* s = k.m_val;
	  uint32_t len = k.m_len;

	  while(--len)
	  {
		  h = h * 101 + (unsigned) *s++;
	  }

	  return h;  
  }
};

class sinsp_table_buffer
{
public:
	sinsp_table_buffer()
	{
		push_buffer();
	}

	~sinsp_table_buffer()
	{
		for(auto it = m_bufs.begin(); it != m_bufs.end(); ++it)
		{
			delete[] *it;
		}
	}

	void push_buffer()
	{
		m_curbuf = new uint8_t[SINSP_TABLE_BUFFER_ENTRY_SIZE];
		m_bufs.push_back(m_curbuf);
		m_pos = 0;
	}

	uint8_t* copy(uint8_t* src, uint32_t len)
	{
		if(m_pos + len >= SINSP_TABLE_BUFFER_ENTRY_SIZE)
		{
			push_buffer();
		}

		uint8_t* dest = m_curbuf + m_pos;
		memcpy(dest, src, len);
		m_pos += len;
		return dest;
	}

	uint8_t* reserve(uint32_t len)
	{
		if(len >= SINSP_TABLE_BUFFER_ENTRY_SIZE)
		{
			ASSERT(false);
			throw sinsp_exception("field value too long");
		}

		if(m_pos + len >= SINSP_TABLE_BUFFER_ENTRY_SIZE)
		{
			push_buffer();
		}

		uint8_t* dest = m_curbuf + m_pos;
		m_pos += len;
		return dest;
	}

	void clear()
	{
		for(auto it = m_bufs.begin(); it != m_bufs.end(); ++it)
		{
			delete[] *it;
		}

		m_bufs.clear();
		push_buffer();
		m_pos = 0;
	}

	vector<uint8_t*> m_bufs;
	uint8_t* m_curbuf;
	uint32_t m_pos;
};

class sinsp_sample_row
{
public:
	sinsp_table_field m_key;
	vector<sinsp_table_field> m_values;
};

class sinsp_table
{
public:	
	enum tabletype
	{
		TT_NONE = 0,
		TT_TABLE,
		TT_LIST,
	};

	enum output_type 
	{
		OT_CURSES,
		OT_RAW,
		OT_JSON,
	};

	sinsp_table(sinsp* inspector, tabletype type, 
		uint64_t refresh_interval_ns, sinsp_table::output_type output_type,
		uint32_t json_first_row, uint32_t json_last_row);
	~sinsp_table();
	void configure(vector<sinsp_view_column_info>* entries, const string& filter, bool use_defaults, uint32_t view_depth);
	void process_event(sinsp_evt* evt);
	void flush(sinsp_evt* evt);
	void filter_sample();
	//
	// Returns the key of the first match, or NULL if no match
	//
	sinsp_table_field* search_in_sample(string text);
	void sort_sample();
	vector<sinsp_sample_row>* get_sample(uint64_t time_delta);
	vector<filtercheck_field_info>* get_legend()
	{
		if(m_do_merging)
		{
			return &m_postmerge_legend;
		}
		else
		{
			return &m_premerge_legend;
		}
	}
	void set_sorting_col(uint32_t col);
	uint32_t get_sorting_col();
	pair<filtercheck_field_info*, string> get_row_key_name_and_val(uint32_t rownum, bool force);
	sinsp_table_field* get_row_key(uint32_t rownum);
	int32_t get_row_from_key(sinsp_table_field* key);
	void set_paused(bool paused);
	void set_freetext_filter(string filter)
	{
		m_freetext_filter = filter;
	}
	tabletype get_type()
	{
		return m_type;
	}
	void set_refresh_interval(uint64_t newinterval_ns)
	{
		m_refresh_interval_ns = newinterval_ns;
	}
	void clear();
	bool is_merging()
	{
		return m_do_merging;
	}
	bool is_sorting_ascending()
	{
		return m_is_sorting_ascending;
	}
	void set_is_sorting_ascending(bool is_sorting_ascending)
	{
		m_is_sorting_ascending = is_sorting_ascending;
	}

	uint64_t m_next_flush_time_ns;
	uint64_t m_prev_flush_time_ns;
	uint64_t m_refresh_interval_ns;
	vector<ppm_param_type>* m_types;
	uint64_t m_json_output_lines_count;

private:
	inline void add_row(bool merging);
	inline void add_fields_sum(ppm_param_type type, sinsp_table_field* dst, sinsp_table_field* src);
	inline void add_fields_sum_of_avg(ppm_param_type type, sinsp_table_field* dst, sinsp_table_field* src);
	inline void add_fields_max(ppm_param_type type, sinsp_table_field* dst, sinsp_table_field* src);
	inline void add_fields_min(ppm_param_type type, sinsp_table_field* dst, sinsp_table_field* src);
	inline void add_fields(uint32_t dst_id, sinsp_table_field* src, uint32_t aggr);
	void process_proctable(sinsp_evt* evt);
	inline uint32_t get_field_len(uint32_t id);
	inline uint8_t* get_default_val(filtercheck_field_info* fld);
	void create_sample();
	void switch_buffers();
	void print_raw(vector<sinsp_sample_row>* sample_data, uint64_t time_delta);
	void print_json(vector<sinsp_sample_row>* sample_data, uint64_t time_delta);

	sinsp* m_inspector;
	unordered_map<sinsp_table_field, sinsp_table_field*, sinsp_table_field_hasher>* m_table;
	unordered_map<sinsp_table_field, sinsp_table_field*, sinsp_table_field_hasher> m_premerge_table;
	unordered_map<sinsp_table_field, sinsp_table_field*, sinsp_table_field_hasher> m_merge_table;
	vector<filtercheck_field_info> m_premerge_legend;
	vector<sinsp_filter_check*> m_premerge_extractors;
	vector<sinsp_filter_check*> m_postmerge_extractors;
	vector<sinsp_filter_check*>* m_extractors;
	vector<sinsp_filter_check*> m_chks_to_free;
	vector<ppm_param_type> m_premerge_types;
	vector<ppm_param_type> m_postmerge_types;
	bool m_is_key_present;
	bool m_is_groupby_key_present;
	vector<uint32_t> m_groupby_columns;
	vector<filtercheck_field_info> m_postmerge_legend;
	sinsp_table_field* m_fld_pointers;
	sinsp_table_field* m_premerge_fld_pointers;
	sinsp_table_field* m_postmerge_fld_pointers;
	uint32_t m_n_fields;
	uint32_t m_n_premerge_fields;
	uint32_t m_n_postmerge_fields;
	sinsp_table_buffer* m_buffer;
	sinsp_table_buffer m_buffer1;
	sinsp_table_buffer m_buffer2;
	uint32_t m_vals_array_sz;
	uint32_t m_premerge_vals_array_sz;
	uint32_t m_postmerge_vals_array_sz;
	sinsp_filter_check_reference* m_printer;
	vector<sinsp_sample_row> m_full_sample_data;
	vector<sinsp_sample_row> m_filtered_sample_data;
	vector<sinsp_sample_row>* m_sample_data;
	sinsp_table_field* m_vals;
	int32_t m_sorting_col;
	bool m_just_sorted;
	bool m_is_sorting_ascending;
	bool m_do_merging;
	sinsp_filter* m_filter;
	bool m_use_defaults;
	uint64_t m_zero_u64;
	uint64_t m_zero_double;
	bool m_paused;
	string m_freetext_filter;
	tabletype m_type;
	output_type m_output_type;
	uint32_t m_view_depth;
	uint32_t m_json_first_row;
	uint32_t m_json_last_row;

	friend class curses_table;	
	friend class sinsp_cursesui;
};
