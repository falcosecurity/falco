#pragma once

////////////////
// Warnings
////////////////

#define WARNING_APPEND "'append' key is deprecated. Add an 'append' entry (e.g. 'condition: append') under 'override' instead."

#define WARNING_ENABLED "The standalone 'enabled' key usage is deprecated. The correct approach requires also a 'replace' entry under the 'override' key (i.e. 'enabled: replace')."

////////////////
// Errors
////////////////

#define ERROR_OVERRIDE_APPEND "Keys 'override' and 'append: true' cannot be used together. Add an 'append' entry (e.g. 'condition: append') under 'override' instead."

#define ERROR_NO_PREVIOUS_MACRO "Macro uses 'append' or 'override.condition: append' but no macro by that name already exists"

#define ERROR_NO_PREVIOUS_LIST "List uses 'append' or 'override.items: append' but no list by that name already exists"

#define ERROR_NO_PREVIOUS_RULE_APPEND "Rule uses 'append' or 'override.<key>: append' but no rule by that name already exists"

#define ERROR_NO_PREVIOUS_RULE_REPLACE "An 'override.<key>: replace' to a rule was requested but no rule by that name already exists"

#define ERROR_INVALID_MACRO_NAME "Macro has an invalid name. Macro names must match a regular expression: "

#define ERROR_INVALID_LIST_NAME "List has an invalid name. List names must match a regular expression: "
