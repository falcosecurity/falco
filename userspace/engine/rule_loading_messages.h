#pragma once

// todo: rename putting error at the beginning
#define OVERRIDE_APPEND_ERROR_MESSAGE "Keys 'override' and 'append: true' cannot be used together. Add an 'append' entry (e.g. 'condition: append') under 'override' instead."

#define WARNING_APPEND_MESSAGE "'append' key is deprecated. Add an 'append' entry (e.g. 'condition: append') under 'override' instead."

#define WARNING_ENABLED_MESSAGE "The standalone 'enabled' key usage is deprecated. The correct approach requires also a 'replace' entry under the 'override' key (i.e. 'enabled: replace')."

#define ERROR_NO_PREVIOUS_MACRO "Macro uses 'append' or 'override.condition: append' but no macro by that name already exists"

#define ERROR_NO_PREVIOUS_LIST "List uses 'append' or 'override.items: append' but no list by that name already exists"

#define ERROR_NO_PREVIOUS_RULE_APPEND "Rule uses 'append' or 'override.<key>: append' but no rule by that name already exists"

#define ERROR_NO_PREVIOUS_RULE_REPLACE "An 'override.<key>: replace' to a rule was requested but no rule by that name already exists"
