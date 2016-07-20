#pragma once

#include <string>

#include "sinsp.h"
#include "filter.h"

#include "rules.h"

#include "falco_common.h"

//
// This class acts as the primary interface between a program and the
// falco rules engine. Falco outputs (writing to files/syslog/etc) are
// handled in a separate class falco_outputs.
//

class falco_engine : public falco_common
{
public:
	falco_engine();
	virtual ~falco_engine();

	//
	// Load rules either directly or from a filename.
	//
	void load_rules_file(const std::string &rules_filename, bool verbose, bool all_events);
	void load_rules(const std::string &rules_content, bool verbose, bool all_events);

	//
	// Enable/Disable any rules matching the provided pattern (regex).
	//
	void enable_rule(std::string &pattern, bool enabled);

	struct rule_result {
		sinsp_evt *evt;
		std::string rule;
		std::string priority;
		std::string format;
	};

	//
	// Given an event, check it against the set of rules in the
	// engine and if a matching rule is found, return details on
	// the rule that matched. If no rule matched, returns NULL.
	//
	// the reutrned rule_result is allocated and must be delete()d.
	rule_result *process_event(sinsp_evt *ev);

	//
	// Print details on the given rule. If rule is NULL, print
	// details on all rules.
	//
	void describe_rule(std::string *rule);

	//
	// Print statistics on how many events matched each rule.
	//
	void print_stats();

	//
	// Add a filter, which is related to the specified list of
	// event types, to the engine.
	//
	void add_evttype_filter(std::string &rule,
				list<uint32_t> &evttypes,
				sinsp_filter* filter);

private:
	falco_rules *m_rules;
        sinsp_evttype_filter m_evttype_filter;

	std::string m_lua_main_filename = "rule_loader.lua";
};

