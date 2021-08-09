/*
Copyright (C) 2021 The Falco Authors.

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

#include <memory>
#include <atomic>

#include <sinsp.h>

#include <falco_engine.h>
#include <falco_engine_embeddable.h>

using namespace std;

class falco_engine_embed_int {
public:
	falco_engine_embed_int();
	virtual ~falco_engine_embed_int();

	bool load_rules_content(string &errstr);
	bool is_open();
	bool open(string &errstr);
	void close();
	falco_engine_embed_rc next_result(falco_engine_embed_result **result, string &errstr);

private:

	static falco_engine_embed_result *rule_result_to_embed_result(gen_event *ev,
								      unique_ptr<falco_engine::rule_result> &res);

	static void add_output_pair(string &field, string &val,
				    char **&fields, char **&vals,
				    uint32_t &len);

	unique_ptr<sinsp_evt_formatter_cache> m_formatters;
	bool m_open;
	unique_ptr<sinsp> m_inspector;
	unique_ptr<falco_engine> m_falco_engine;
	atomic<bool> m_shutdown;
};

falco_engine_embed_int::falco_engine_embed_int()
        : m_open(false),
	m_shutdown(false)
{
	m_inspector.reset(new sinsp());
	m_falco_engine.reset(new falco_engine());

	m_formatters = make_unique<sinsp_evt_formatter_cache>(m_inspector.get());
}

falco_engine_embed_int::~falco_engine_embed_int()
{
}

bool falco_engine_embed_int::load_rules_content(const char *rules_content, string &err)
{
	bool verbose = false;
	bool all_events = true;

	try {
		m_falco_engine->load_rules(string(rules_content), verbose, all_events);
	}
	catch(falco_exception &e)
	{
		err = e.what();
		return false;
	}

	return true;
}

bool falco_engine_embed::is_open()
{
	return m_open;
}

bool falco_engine_embed_int::open(string &err)
{
	try {
		m_inspector->open();
	}
	catch(exception &e)
	{
		err = e.what();
		return false;
	}

	return true;
}

void falco_engine_embed_int::close()
{
	m_shutdown = true;
}

falco_engine_embed_rc next_result(falco_engine_embed_result **result, string &err)
{
	*result = NULL;

	while(!m_shutdown)
	{
		int32_t rc = inspector->next(&ev);

		if (rc == SCAP_TIMEOUT)
		{
			continue;
		}
		else if (rc == SCAP_EOF)
		{
			break;
		}
		else if (rc != SCAP_SUCCESS)
		{
			err = m_inspector->getlasterr();
			return FE_EMB_RC_ERROR;
		}

		if(!ev->simple_consumer_consider())
		{
			continue;
		}

		unique_ptr<falco_engine::rule_result> res = engine->process_sinsp_event(ev);
		if(!res)
		{
			continue;
		}

		*result = rule_result_to_embed_result(ev, res);

		return FE_EMB_RC_OK;
	}

	// Can only get here if shut down/eof.
	return FE_EMB_RC_EOF:
}

falco_engine_embed_result * falco_engine_embed_int::rule_result_to_embed_result(gen_event *ev,
										unique_ptr<falco_engine::rule_result> &res)
{
	falco_engine_embed_result *result;

	result = (falco_engine_embed_result *) malloc(sizeof(falco_engine_embed_result));

	result->rule = strdup(res->rule.c_str());
	result->event_source = strdup(res->source.c_str());
	result->priority_num = res->priority_num;

	// Copy output format string without resolving fields.
	result->output_format_str = res->format;

	// Resolve output format string into resolved output
	string output;
	m_formatters->tostring(ev, res->format, &output);
	result->output_str = strdup(output.c_str());

	map<string, string> rule_output_fields;
	m_formatters->resolve_tokens(evt, res->format, rule_output_fields);
	for(auto &pair : rule_output_fields)
	{
		add_output_pair(pair.first, pair.second,
				result->output_fields, result->output_values,
				result->num_output_values);
	}

	// Preceding * makes the formatting permissive (not ending at first empty value)
	std::string exformat = "*";
	for (const auto& exfield : res->exception_fields)
	{
		exformat += " %" + exfield;
	}

	map<string, string> exception_output_fields;
	m_formatters->resolve_tokens(evt, exformat, exception_output_fields);
	for(auto &pair : exception_output_fields)
	{
		add_output_pair(pair.first, pair.second,
				result->output_fields, result->output_values,
				result->num_output_values);
	}

	return result;
}

falco_engine_embed_int::add_output_pair(string &field, string &val,
					char **&fields, char **&vals,
					uint32_t len)
{
	len++;
	fields = (char **) realloc(fields, len*sizeof(char *));
	vals = (char **) realloc(vals, len*sizeof(char *));
	fields[len-1] = strdup(field.c_str());
	vals[len-1] = strdup(val.c_str());
}

static const char *FALCO_ENGINE_EMBED_VERSION = "1.0.0";

char *falco_engine_embed_get_version()
{
	return strdup(FALCO_ENGINE_EMBED_VERSION);
}

void falco_engine_embed_free_result(falco_engine_embed_result *result);
{
	free(result->rule);
	free(result->event_source);
	free(result->output_format_str);
	free(result->output_str);

	for(int32_t i; i < result->num_output_values; i++)
	{
		free(result->output_fields[i]);
		free(result->output_values[i]);
	}
	free(result->output_fields);
	free(result->output_values);
	free(result);
}

falco_engine_embed_t* falco_engine_embed_init(int32_t *rc)
{
	falco_engine_embed_int *eengine = new falco_engine_embed_int();

	*rc = FE_EMB_RC_OK;

	return eengine;
}

int32_t falco_engine_embed_destroy(falco_engine_embed_t *engine, char *errstr)
{
	eengine = (falco_engine_embed_int *) engine;

	if(eengine->is_open())
	{
		errstr = strdup("Engine is open--must call close() first");
		return FE_EMB_RC_ERROR:
	}

	delete(eengine);

	return FE_EMB_RC_OK;
}

int32_t falco_engine_embed_load_plugin(falco_engine_embed_t *engine,
				       const char *path,
				       const char* init_config,
				       const char* open_params,
				       char **errstr)
{
	eengine = (falco_engine_embed_int *) engine;

	// XXX/mstemm fill in
	return FE_EMB_RC_OK;
}

int32_t falco_engine_embed_load_rules_content(falco_engine_embed_t *engine,
					      const char *rules_content,
					      char **errstr)
{
	eengine = (falco_engine_embed_int *) engine;
	std::string err;

	if (!eengine->load_rules_content(err))
	{
		errstr = strdup(err.c_str());
		return FE_EMB_RC_ERROR;
	}

	return FE_EMB_RC_OK;
}

int32_t falco_engine_embed_enable_source(falco_engine_embed_t *engine,
					 source int32_t,
					 bool enabled,
					 char **errstr)
{
	eengine = (falco_engine_embed_int *) engine;

	// XXX/mstemm fill in
	return FE_EMB_RC_OK;
}

int32_t falco_engine_embed_open(falco_engine_embed_t *engine,
				char **errstr)
{
	eengine = (falco_engine_embed_int *) engine;
	std::string err;

	if (!eengine->open(err))
	{
		errstr = strdup(err.c_str());
		return FE_EMB_RC_ERROR;
	}

	return FE_EMB_RC_OK;
}

int32_t falco_engine_embed_close(falco_engine_embed_t *engine,
				 char **errstr)
{
	eengine = (falco_engine_embed_int *) engine;
	std::string err;

	if (!eengine->close(err))
	{
		errstr = strdup(err.c_str());
		return FE_EMB_RC_ERROR;
	}

	return FE_EMB_RC_OK;
}

int32_t falco_engine_embed_next_result(falco_engine_embed_t *engine,
				       falco_engine_embed_result **result,
				       char **errstr)
{
	eengine = (falco_engine_embed_int *) engine;
	std::string err;
	falco_engine_embed_rc rc;

	rc = eengine->next_result(falco_engine_embed_result, err);

	if(rc == FE_EMB_RC_ERROR)
	{
		errstr = strdup(err.c_str());
	}

	return rc;
}


