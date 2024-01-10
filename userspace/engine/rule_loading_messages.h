#pragma once

// Error message used when both 'override' and 'append' keys are specified.
#define OVERRIDE_APPEND_ERROR_MESSAGE "Keys 'override' and 'append: true' cannot be used together. Add an 'append' entry (e.g. 'condition: append') under 'override' instead."

// Warning message used when 'append' key is used.
#define WARNING_APPEND_MESSAGE "'append' key is deprecated. Add an 'append' entry (e.g. 'condition: append') under 'override' instead."

// Warning message used when 'enabled' is used without 'override' key.
#define WARNING_ENABLED_MESSAGE "The standalone 'enabled' key usage is deprecated. The correct approach requires also a 'replace' entry under the 'override' key (i.e. 'enabled: replace')."

#define ERROR_NO_PREVIOUS_MACRO "Macro uses 'append' or 'override.condition: append' but no macro by that name already exists"

#define ERROR_NO_PREVIOUS_LIST "List uses 'append' or 'override.items: append' but no list by that name already exists"

#define ERROR_NO_PREVIOUS_RULE "Rule uses 'append' or 'override.<key>: append' but no rule by that name already exists"
