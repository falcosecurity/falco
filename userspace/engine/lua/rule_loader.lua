-- Copyright (C) 2019 The Falco Authors.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

--[[
   Compile and install falco rules.

   This module exports functions that are called from falco c++-side to compile and install a set of rules.

--]]

local sinsp_rule_utils = require "sinsp_rule_utils"
local compiler = require "compiler"
local yaml = require"lyaml"


--[[
   Traverse AST, adding the passed-in 'index' to each node that contains a relational expression
--]]
local function mark_relational_nodes(ast, index)
   local t = ast.type

   if t == "BinaryBoolOp" then
      mark_relational_nodes(ast.left, index)
      mark_relational_nodes(ast.right, index)

   elseif t == "UnaryBoolOp" then
      mark_relational_nodes(ast.argument, index)

   elseif t == "BinaryRelOp" then
      ast.index = index

   elseif t == "UnaryRelOp"  then
      ast.index = index

   else
      error ("Unexpected type in mark_relational_nodes: "..t)
   end
end

function map(f, arr)
   local res = {}
   for i,v in ipairs(arr) do
      res[i] = f(v)
   end
   return res
end


-- Permissive for case and for common abbreviations.
priorities = {
   Emergency=0, Alert=1, Critical=2, Error=3, Warning=4, Notice=5, Informational=5, Debug=7,
   emergency=0, alert=1, critical=2, error=3, warning=4, notice=5, informational=5, debug=7,
   EMERGENCY=0, ALERT=1, CRITICAL=2, ERROR=3, WARNING=4, NOTICE=5, INFORMATIONAL=5, DEBUG=7,
   INFO=5, info=5
}

--[[
   Take a filter AST and set it up in the libsinsp runtime, using the filter API.
--]]
local function install_filter(node, filter_api_lib, lua_parser, parent_bool_op)
   local t = node.type

   if t == "BinaryBoolOp" then

      -- "nesting" (the runtime equivalent of placing parens in syntax) is
      -- never necessary when we have identical successive operators. so we
      -- avoid it as a runtime performance optimization.
      if (not(node.operator == parent_bool_op)) then
	 filter_api_lib.nest(lua_parser) -- io.write("(")
      end

      install_filter(node.left, filter_api_lib, lua_parser, node.operator)
      filter_api_lib.bool_op(lua_parser, node.operator) -- io.write(" "..node.operator.." ")
      install_filter(node.right, filter_api_lib, lua_parser, node.operator)

      if (not (node.operator == parent_bool_op)) then
	 filter_api_lib.unnest(lua_parser) -- io.write(")")
      end

   elseif t == "UnaryBoolOp" then
      filter_api_lib.nest(lua_parser) --io.write("(")
      filter_api_lib.bool_op(lua_parser, node.operator) -- io.write(" "..node.operator.." ")
      install_filter(node.argument, filter_api_lib, lua_parser)
      filter_api_lib.unnest(lua_parser) -- io.write(")")

   elseif t == "BinaryRelOp" then
      if (node.operator == "in" or
          node.operator == "intersects" or
	  node.operator == "pmatch") then
	 elements = map(function (el) return el.value end, node.right.elements)
	 filter_api_lib.rel_expr(lua_parser, node.left.value, node.operator, elements, node.index)
      else
	 filter_api_lib.rel_expr(lua_parser, node.left.value, node.operator, node.right.value, node.index)
      end
      -- io.write(node.left.value.." "..node.operator.." "..node.right.value)

   elseif t == "UnaryRelOp"  then
      filter_api_lib.rel_expr(lua_parser, node.argument.value, node.operator, node.index)
      --io.write(node.argument.value.." "..node.operator)

   else
      error ("Unexpected type in install_filter: "..t)
   end
end

function set_output(output_format, state)

   if(output_ast.type == "OutputFormat") then

      local format

   else
      error ("Unexpected type in set_output: ".. output_ast.type)
   end
end

-- Note that the rules_by_name and rules_by_idx refer to the same rule
-- object. The by_name index is used for things like describing rules,
-- and the by_idx index is used to map the relational node index back
-- to a rule.
local state = {macros={}, lists={}, filter_ast=nil, rules_by_name={},
	       skipped_rules_by_name={}, macros_by_name={}, lists_by_name={},
	       n_rules=0, rules_by_idx={}, ordered_rule_names={}, ordered_macro_names={}, ordered_list_names={}}

local function reset_rules(rules_mgr)
   falco_rules.clear_filters(rules_mgr)
   state.n_rules = 0
   state.rules_by_idx = {}
   state.macros = {}
   state.lists = {}
end

-- From http://lua-users.org/wiki/TableUtils
--
function table.val_to_str ( v )
  if "string" == type( v ) then
    v = string.gsub( v, "\n", "\\n" )
    if string.match( string.gsub(v,"[^'\"]",""), '^"+$' ) then
      return "'" .. v .. "'"
    end
    return '"' .. string.gsub(v,'"', '\\"' ) .. '"'
  else
    return "table" == type( v ) and table.tostring( v ) or
      tostring( v )
  end
end

function table.key_to_str ( k )
  if "string" == type( k ) and string.match( k, "^[_%a][_%a%d]*$" ) then
    return k
  else
    return "[" .. table.val_to_str( k ) .. "]"
  end
end

function table.tostring( tbl )
  local result, done = {}, {}
  for k, v in ipairs( tbl ) do
    table.insert( result, table.val_to_str( v ) )
    done[ k ] = true
  end
  for k, v in pairs( tbl ) do
    if not done[ k ] then
      table.insert( result,
        table.key_to_str( k ) .. "=" .. table.val_to_str( v ) )
    end
  end
  return "{" .. table.concat( result, "," ) .. "}"
end

-- Split rules_content by lines and also remember the line numbers for
-- each top -level object. Returns a table of lines and a table of
-- line numbers for objects.

function split_lines(rules_content)
   lines = {}
   indices = {}

   idx = 1
   last_pos = 1
   pos = string.find(rules_content, "\n", 1, true)

   while pos ~= nil do
      line = string.sub(rules_content, last_pos, pos-1)
      if line ~= "" then
	 lines[#lines+1] = line
	 if string.len(line) >= 3 and string.sub(line, 1, 3) == "---" then
	    -- Document marker, skip
         elseif string.sub(line, 1, 1) == '-' then
	    indices[#indices+1] = idx
	 end

	 idx = idx + 1
      end

      last_pos = pos+1
      pos = string.find(rules_content, "\n", pos+1, true)
   end

   if last_pos < string.len(rules_content) then
      line = string.sub(rules_content, last_pos)
      lines[#lines+1] = line
      if string.sub(line, 1, 1) == '-' then
	 indices[#indices+1] = idx
      end

      idx = idx + 1
   end

   -- Add a final index for last line in document
   indices[#indices+1] = idx

   return lines, indices
end

function get_orig_yaml_obj(rules_lines, row)
   local ret = ""

   idx = row
   while (idx <= #rules_lines) do
      ret = ret..rules_lines[idx].."\n"
      idx = idx + 1

      if idx > #rules_lines or rules_lines[idx] == "" or string.sub(rules_lines[idx], 1, 1) == '-' then
	 break
      end
   end

   return ret
end

function get_lines(rules_lines, row, num_lines)
   local ret = ""

   idx = row
   while (idx < (row + num_lines) and idx <= #rules_lines) do
      ret = ret..rules_lines[idx].."\n"
      idx = idx + 1
   end

   return ret
end

function build_error(rules_lines, row, num_lines, err)
   local ret = err.."\n---\n"..get_lines(rules_lines, row, num_lines).."---"

   return ret
end

function build_error_with_context(ctx, err)
   local ret = err.."\n---\n"..ctx.."---"
   return ret
end

function load_rules_doc(rules_mgr, doc, load_state)

   -- Iterate over yaml list. In this pass, all we're doing is
   -- populating the set of rules, macros, and lists. We're not
   -- expanding/compiling anything yet. All that will happen in a
   -- second pass
   for i,v in ipairs(doc) do

      load_state.cur_item_idx = load_state.cur_item_idx + 1

      -- Save back the original object as it appeared in the file. Will be used to provide context.
      local context = get_orig_yaml_obj(load_state.lines,
					load_state.indices[load_state.cur_item_idx])

      if (not (type(v) == "table")) then
	 return false, build_error_with_context(context, "Unexpected element of type " ..type(v)..". Each element should be a yaml associative array.")
      end

      v['context'] = context

      if (v['required_engine_version']) then
	 load_state.required_engine_version = v['required_engine_version']
	 if type(load_state.required_engine_version) ~= "number" then
	    return false, build_error_with_context(v['context'], "Value of required_engine_version must be a number")
	 end

	 if falco_rules.engine_version(rules_mgr) < v['required_engine_version'] then
	    return false, build_error_with_context(v['context'], "Rules require engine version "..v['required_engine_version']..", but engine version is "..falco_rules.engine_version(rules_mgr))
	 end

      elseif (v['macro']) then

	 if (v['macro'] == nil or type(v['macro']) == "table") then
	    return false, build_error_with_context(v['context'], "Macro name is empty")
	 end

	 if v['source'] == nil then
	    v['source'] = "syscall"
	 end

	 if state.macros_by_name[v['macro']] == nil then
	    state.ordered_macro_names[#state.ordered_macro_names+1] = v['macro']
	 end

	 for j, field in ipairs({'condition'}) do
	    if (v[field] == nil) then
	       return false, build_error_with_context(v['context'], "Macro must have property "..field)
	    end
	 end

	 -- Possibly append to the condition field of an existing macro
	 append = false

	 if v['append'] then
	    append = v['append']
	 end

	 if append then
	    if state.macros_by_name[v['macro']] == nil then
	       return false, build_error_with_context(v['context'], "Macro " ..v['macro'].. " has 'append' key but no macro by that name already exists")
	    end

	    state.macros_by_name[v['macro']]['condition'] = state.macros_by_name[v['macro']]['condition'] .. " " .. v['condition']

	    -- Add the current object to the context of the base macro
	    state.macros_by_name[v['macro']]['context'] = state.macros_by_name[v['macro']]['context'].."\n"..v['context']

	 else
	    state.macros_by_name[v['macro']] = v
	 end

      elseif (v['list']) then

	 if (v['list'] == nil or type(v['list']) == "table") then
	    return false, build_error_with_context(v['context'], "List name is empty")
	 end

	 if state.lists_by_name[v['list']] == nil then
	    state.ordered_list_names[#state.ordered_list_names+1] = v['list']
	 end

	 for j, field in ipairs({'items'}) do
	    if (v[field] == nil) then
	       return false, build_error_with_context(v['context'], "List must have property "..field)
	    end
	 end

	 -- Possibly append to an existing list
	 append = false

	 if v['append'] then
	    append = v['append']
	 end

	 if append then
	    if state.lists_by_name[v['list']] == nil then
	       return false, build_error_with_context(v['context'], "List " ..v['list'].. " has 'append' key but no list by that name already exists")
	    end

	    for j, elem in ipairs(v['items']) do
	       table.insert(state.lists_by_name[v['list']]['items'], elem)
	    end
	 else
	    state.lists_by_name[v['list']] = v
	 end

      elseif (v['rule']) then

	 if (v['rule'] == nil or type(v['rule']) == "table") then
	    return false, build_error_with_context(v['context'], "Rule name is empty")
	 end

	 -- By default, if a rule's condition refers to an unknown
	 -- filter like evt.type, etc the loader throws an error.
	 if v['skip-if-unknown-filter'] == nil then
	    v['skip-if-unknown-filter'] = false
	 end

	 if v['source'] == nil then
	    v['source'] = "syscall"
	 end

	 -- Possibly append to the condition field of an existing rule
	 append = false

	 if v['append'] then
	    append = v['append']
	 end

	 if append then

	    -- For append rules, all you need is the condition
	    for j, field in ipairs({'condition'}) do
	       if (v[field] == nil) then
		  return false, build_error_with_context(v['context'], "Rule must have property "..field)
	       end
	    end

	    if state.rules_by_name[v['rule']] == nil then
	       if state.skipped_rules_by_name[v['rule']] == nil then
		  return false, build_error_with_context(v['context'], "Rule " ..v['rule'].. " has 'append' key but no rule by that name already exists")
	       end
	    else
	       state.rules_by_name[v['rule']]['condition'] = state.rules_by_name[v['rule']]['condition'] .. " " .. v['condition']

	    -- Add the current object to the context of the base rule
	       state.rules_by_name[v['rule']]['context'] = state.rules_by_name[v['rule']]['context'].."\n"..v['context']
	    end

	 else

	    for j, field in ipairs({'condition', 'output', 'desc', 'priority'}) do
	       if (v[field] == nil) then
		  return false, build_error_with_context(v['context'], "Rule must have property "..field)
	       end
	    end

	    -- Convert the priority-as-string to a priority-as-number now
	    v['priority_num'] = priorities[v['priority']]

	    if v['priority_num'] == nil then
	       error("Invalid priority level: "..v['priority'])
	    end

	    if v['priority_num'] <= load_state.min_priority then
	       -- Note that we can overwrite rules, but the rules are still
	       -- loaded in the order in which they first appeared,
	       -- potentially across multiple files.
	       if state.rules_by_name[v['rule']] == nil then
		  state.ordered_rule_names[#state.ordered_rule_names+1] = v['rule']
	       end

	       -- The output field might be a folded-style, which adds a
	       -- newline to the end. Remove any trailing newlines.
	       v['output'] = compiler.trim(v['output'])

	       state.rules_by_name[v['rule']] = v
	    else
	       state.skipped_rules_by_name[v['rule']] = v
	    end
	 end
      else
	 -- Remove the context from the table, so the table is exactly what was parsed
	 local context = v['context']
	 v['context'] = nil
	 return false, build_error_with_context(context, "Unknown rule object: "..table.tostring(v))
      end
   end

   return true, ""
end

function load_rules(sinsp_lua_parser,
		    json_lua_parser,
		    rules_content,
		    rules_mgr,
		    verbose,
		    all_events,
		    extra,
		    replace_container_info,
		    min_priority)

   local load_state = {lines={}, indices={}, cur_item_idx=0, min_priority=min_priority, required_engine_version=0}

   load_state.lines, load_state.indices = split_lines(rules_content)

   local status, docs = pcall(yaml.load, rules_content, { all = true })

   if status == false then
      local pat = "^([%d]+):([%d]+): "
      -- docs is actually an error string

      local row = 0
      local col = 0

      row, col = string.match(docs, pat)
      if row ~= nil and col ~= nil then
	 docs = string.gsub(docs, pat, "")
      end

      row = tonumber(row)
      col = tonumber(col)

      return false, build_error(load_state.lines, row, 3, docs)
   end

   if docs == nil then
      -- An empty rules file is acceptable
      return true, load_state.required_engine_version
   end

   if type(docs) ~= "table" then
      return false, build_error(load_state.lines, 1, 1, "Rules content is not yaml")
   end

   for docidx, doc in ipairs(docs) do

      if type(doc) ~= "table" then
	 return false, build_error(load_state.lines, 1, 1, "Rules content is not yaml")
      end

      -- Look for non-numeric indices--implies that document is not array
      -- of objects.
      for key, val in pairs(doc) do
	 if type(key) ~= "number" then
	    return false, build_error(load_state.lines, 1, 1, "Rules content is not yaml array of objects")
	 end
      end

      res, errstr = load_rules_doc(rules_mgr, doc, load_state)

      if not res then
	 return res, errstr
      end
   end

   -- We've now loaded all the rules, macros, and lists. Now
   -- compile/expand the rules, macros, and lists. We use
   -- ordered_rule_{lists,macros,names} to compile them in the order
   -- in which they appeared in the file(s).
   reset_rules(rules_mgr)

   for i, name in ipairs(state.ordered_list_names) do

      local v = state.lists_by_name[name]

      -- list items are represented in yaml as a native list, so no
      -- parsing necessary
      local items = {}

      -- List items may be references to other lists, so go through
      -- the items and expand any references to the items in the list
      for i, item in ipairs(v['items']) do
	 if (state.lists[item] == nil) then
	    items[#items+1] = item
	 else
	    for i, exp_item in ipairs(state.lists[item].items) do
	       items[#items+1] = exp_item
	    end
	 end
      end

      state.lists[v['list']] = {["items"] = items, ["used"] = false}
   end

   for _, name in ipairs(state.ordered_macro_names) do

      local v = state.macros_by_name[name]

      local status, ast = compiler.compile_macro(v['condition'], state.macros, state.lists)

      if status == false then
	 return false, build_error_with_context(v['context'], ast)
      end

      if v['source'] == "syscall" then
	 if not all_events then
	    sinsp_rule_utils.check_for_ignored_syscalls_events(ast, 'macro', v['condition'])
	 end
      end

      state.macros[v['macro']] = {["ast"] = ast.filter.value, ["used"] = false}
   end

   for _, name in ipairs(state.ordered_rule_names) do

      local v = state.rules_by_name[name]

      warn_evttypes = true
      if v['warn_evttypes'] ~= nil then
	 warn_evttypes = v['warn_evttypes']
      end

      local status, filter_ast, filters = compiler.compile_filter(v['rule'], v['condition'],
								  state.macros, state.lists)

      if status == false then
	 return false, build_error_with_context(v['context'], filter_ast)
      end

      local evtttypes = {}
      local syscallnums = {}

      if v['source'] == "syscall" then
	 if not all_events then
	    sinsp_rule_utils.check_for_ignored_syscalls_events(filter_ast, 'rule', v['rule'])
	 end

	 evttypes, syscallnums = sinsp_rule_utils.get_evttypes_syscalls(name, filter_ast, v['condition'], warn_evttypes, verbose)
      end

      -- If a filter in the rule doesn't exist, either skip the rule
      -- or raise an error, depending on the value of
      -- skip-if-unknown-filter.
      for filter, _ in pairs(filters) do
	 found = false

	 if defined_noarg_filters[filter] ~= nil then
	    found = true
	 else
	    bracket_idx = string.find(filter, "[", 1, true)

	    if bracket_idx ~= nil then
	       subfilter = string.sub(filter, 1, bracket_idx-1)

	       if defined_arg_filters[subfilter] ~= nil then
		  found = true
	       end
	    end

	    if not found then
	       dot_idx = string.find(filter, ".", 1, true)

	       while dot_idx ~= nil do
		  subfilter = string.sub(filter, 1, dot_idx-1)

		  if defined_arg_filters[subfilter] ~= nil then
		     found = true
		     break
		  end

		  dot_idx = string.find(filter, ".", dot_idx+1, true)
	       end
	    end
	 end

	 if not found then
	    if v['skip-if-unknown-filter'] then
	       if verbose then
		  print("Skipping rule \""..v['rule'].."\" that contains unknown filter "..filter)
	       end
	       goto next_rule
	    else
	       error("Rule \""..v['rule'].."\" contains unknown filter "..filter)
	    end
	 end
      end

      if (filter_ast.type == "Rule") then
	 state.n_rules = state.n_rules + 1

	 state.rules_by_idx[state.n_rules] = v

	 -- Store the index of this formatter in each relational expression that
	 -- this rule contains.
	 -- This index will eventually be stamped in events passing this rule, and
	 -- we'll use it later to determine which output to display when we get an
	 -- event.
	 mark_relational_nodes(filter_ast.filter.value, state.n_rules)

	 if (v['tags'] == nil) then
	    v['tags'] = {}
	 end
	 if v['source'] == "syscall" then
	    install_filter(filter_ast.filter.value, filter, sinsp_lua_parser)
	    -- Pass the filter and event types back up
	    falco_rules.add_filter(rules_mgr, v['rule'], evttypes, syscallnums, v['tags'])

	 elseif v['source'] == "k8s_audit" then
	    install_filter(filter_ast.filter.value, k8s_audit_filter, json_lua_parser)

	    falco_rules.add_k8s_audit_filter(rules_mgr, v['rule'], v['tags'])
	 end

	 -- Rule ASTs are merged together into one big AST, with "OR" between each
	 -- rule.
	 if (state.filter_ast == nil) then
	    state.filter_ast = filter_ast.filter.value
	 else
	    state.filter_ast = { type = "BinaryBoolOp", operator = "or", left = state.filter_ast, right = filter_ast.filter.value }
	 end

	 -- Enable/disable the rule
	 if (v['enabled'] == nil) then
	    v['enabled'] = true
	 end

	 if (v['enabled'] == false) then
	    falco_rules.enable_rule(rules_mgr, v['rule'], 0)
	 else
	    falco_rules.enable_rule(rules_mgr, v['rule'], 1)
	 end

	 -- If the format string contains %container.info, replace it
	 -- with extra. Otherwise, add extra onto the end of the format
	 -- string.
	 if v['source'] == "syscall" then
	    if string.find(v['output'], "%container.info", nil, true) ~= nil then

	       -- There may not be any extra, or we're not supposed
	       -- to replace it, in which case we use the generic
	       -- "%container.name (id=%container.id)"
	       if replace_container_info == false then
		  v['output'] = string.gsub(v['output'], "%%container.info", "%%container.name (id=%%container.id)")
		  if extra ~= "" then
		     v['output'] = v['output'].." "..extra
		  end
	       else
		  safe_extra = string.gsub(extra, "%%", "%%%%")
		  v['output'] = string.gsub(v['output'], "%%container.info", safe_extra)
	       end
	    else
	       -- Just add the extra to the end
	       if extra ~= "" then
		  v['output'] = v['output'].." "..extra
	       end
	    end
	 end

	 -- Ensure that the output field is properly formatted by
	 -- creating a formatter from it. Any error will be thrown
	 -- up to the top level.
	 formatter = formats.formatter(v['source'], v['output'])
	 formats.free_formatter(v['source'], formatter)
      else
	 return false, build_error_with_context(v['context'], "Unexpected type in load_rule: "..filter_ast.type)
      end

      ::next_rule::
   end

   if verbose then
      -- Print info on any dangling lists or macros that were not used anywhere
      for name, macro in pairs(state.macros) do
	 if macro.used == false then
	    print("Warning: macro "..name.." not refered to by any rule/macro")
	 end
      end

      for name, list in pairs(state.lists) do
	 if list.used == false then
	    print("Warning: list "..name.." not refered to by any rule/macro/list")
	 end
      end
   end

   io.flush()

   return true, load_state.required_engine_version
end

local rule_fmt = "%-50s %s"

-- http://lua-users.org/wiki/StringRecipes, with simplifications and bugfixes
local function wrap(str, limit, indent)
   indent = indent or ""
   limit = limit or 72
   local here = 1
   return str:gsub("(%s+)()(%S+)()",
		   function(sp, st, word, fi)
		      if fi-here > limit then
			 here = st
			 return "\n"..indent..word
		      end
                   end)
end

local function describe_single_rule(name)
   if (state.rules_by_name[name] == nil) then
      error ("No such rule: "..name)
   end

   -- Wrap the description into an multiple lines each of length ~ 60
   -- chars, with indenting to line up with the first line.
   local wrapped = wrap(state.rules_by_name[name]['desc'], 60, string.format(rule_fmt, "", ""))

   local line = string.format(rule_fmt, name, wrapped)
   print(line)
   print()
end

-- If name is nil, describe all rules
function describe_rule(name)

   print()
   local line = string.format(rule_fmt, "Rule", "Description")
   print(line)
   line = string.format(rule_fmt, "----", "-----------")
   print(line)

   if name == nil then
      for rulename, rule in pairs(state.rules_by_name) do
	 describe_single_rule(rulename)
      end
   else
      describe_single_rule(name)
   end
end

local rule_output_counts = {total=0, by_priority={}, by_name={}}

function on_event(rule_id)

   if state.rules_by_idx[rule_id] == nil then
      error ("rule_loader.on_event(): event with invalid rule_id: ", rule_id)
   end

   rule_output_counts.total = rule_output_counts.total + 1
   local rule = state.rules_by_idx[rule_id]

   if rule_output_counts.by_priority[rule.priority] == nil then
      rule_output_counts.by_priority[rule.priority] = 1
   else
      rule_output_counts.by_priority[rule.priority] = rule_output_counts.by_priority[rule.priority] + 1
   end

   if rule_output_counts.by_name[rule.rule] == nil then
      rule_output_counts.by_name[rule.rule] = 1
   else
      rule_output_counts.by_name[rule.rule] = rule_output_counts.by_name[rule.rule] + 1
   end

   -- Prefix output with '*' so formatting is permissive
   output = "*"..rule.output

   return rule.rule, rule.priority_num, output
end

function print_stats()
   print("Events detected: "..rule_output_counts.total)
   print("Rule counts by severity:")
   for priority, count in pairs(rule_output_counts.by_priority) do
      print ("   "..priority..": "..count)
   end

   print("Triggered rules by rule name:")
   for name, count in pairs(rule_output_counts.by_name) do
      print ("   "..name..": "..count)
   end
end



