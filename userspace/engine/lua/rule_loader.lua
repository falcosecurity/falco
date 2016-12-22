--
-- Copyright (C) 2016 Draios inc.
--
-- This file is part of falco.
--
-- falco is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License version 2 as
-- published by the Free Software Foundation.
--
-- falco is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with falco.  If not, see <http://www.gnu.org/licenses/>.

--[[
   Compile and install falco rules.

   This module exports functions that are called from falco c++-side to compile and install a set of rules.

--]]

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


--[[
   Take a filter AST and set it up in the libsinsp runtime, using the filter API.
--]]
local function install_filter(node, parent_bool_op)
   local t = node.type

   if t == "BinaryBoolOp" then

      -- "nesting" (the runtime equivalent of placing parens in syntax) is
      -- never necessary when we have identical successive operators. so we
      -- avoid it as a runtime performance optimization.
      if (not(node.operator == parent_bool_op)) then
	 filter.nest() -- io.write("(")
      end

      install_filter(node.left, node.operator)
      filter.bool_op(node.operator) -- io.write(" "..node.operator.." ")
      install_filter(node.right, node.operator)

      if (not (node.operator == parent_bool_op)) then
	 filter.unnest() -- io.write(")")
      end

   elseif t == "UnaryBoolOp" then
      filter.nest() --io.write("(")
      filter.bool_op(node.operator) -- io.write(" "..node.operator.." ")
      install_filter(node.argument)
      filter.unnest() -- io.write(")")

   elseif t == "BinaryRelOp" then
      if (node.operator == "in" or node.operator == "pmatch") then
	 elements = map(function (el) return el.value end, node.right.elements)
	 filter.rel_expr(node.left.value, node.operator, elements, node.index)
      else
	 filter.rel_expr(node.left.value, node.operator, node.right.value, node.index)
      end
      -- io.write(node.left.value.." "..node.operator.." "..node.right.value)

   elseif t == "UnaryRelOp"  then
      filter.rel_expr(node.argument.value, node.operator, node.index)
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
local state = {macros={}, lists={}, filter_ast=nil, rules_by_name={}, n_rules=0, rules_by_idx={}}

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


function load_rules(rules_content, rules_mgr, verbose, all_events, extra, replace_container_info)

   compiler.set_verbose(verbose)
   compiler.set_all_events(all_events)

   local rules = yaml.load(rules_content)

   if rules == nil then
      -- An empty rules file is acceptable
      return
   end

   if type(rules) ~= "table" then
      error("Rules content \""..rules_content.."\" is not yaml")
   end

   for i,v in ipairs(rules) do -- iterate over yaml list

      if (not (type(v) == "table")) then
	 error ("Unexpected element of type " ..type(v)..". Each element should be a yaml associative array.")
      end

      if (v['macro']) then
	 local ast = compiler.compile_macro(v['condition'], state.lists)
	 state.macros[v['macro']] = ast.filter.value

      elseif (v['list']) then
	 -- list items are represented in yaml as a native list, so no
	 -- parsing necessary
	 local items = {}

	 -- List items may be references to other lists, so go through
	 -- the items and expand any references to the items in the list
	 for i, item in ipairs(v['items']) do
	    if (state.lists[item] == nil) then
	       items[#items+1] = item
	    else
	       for i, exp_item in ipairs(state.lists[item]) do
		  items[#items+1] = exp_item
	       end
	    end
	 end

	 state.lists[v['list']] = items

      elseif (v['rule']) then

	 if (v['rule'] == nil or type(v['rule']) == "table") then
	    error ("Missing name in rule")
	 end

	 for i, field in ipairs({'condition', 'output', 'desc', 'priority'}) do
	    if (v[field] == nil) then
	       error ("Missing "..field.." in rule with name "..v['rule'])
	    end
	 end

	 state.rules_by_name[v['rule']] = v

	 local filter_ast, evttypes = compiler.compile_filter(v['rule'], v['condition'],
							      state.macros, state.lists)

	 if (filter_ast.type == "Rule") then
	    state.n_rules = state.n_rules + 1

	    state.rules_by_idx[state.n_rules] = v

	    -- Store the index of this formatter in each relational expression that
	    -- this rule contains.
	    -- This index will eventually be stamped in events passing this rule, and
	    -- we'll use it later to determine which output to display when we get an
	    -- event.
	    mark_relational_nodes(filter_ast.filter.value, state.n_rules)

	    install_filter(filter_ast.filter.value)

	    -- Pass the filter and event types back up
	    falco_rules.add_filter(rules_mgr, v['rule'], evttypes)

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
	    end

	    -- If the format string contains %container.info, replace it
	    -- with extra. Otherwise, add extra onto the end of the format
	    -- string.
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

	    -- Ensure that the output field is properly formatted by
	    -- creating a formatter from it. Any error will be thrown
	    -- up to the top level.
	    formatter = formats.formatter(v['output'])
	    formats.free_formatter(formatter)
	 else
	    error ("Unexpected type in load_rule: "..filter_ast.type)
	 end
      else
	 error ("Unknown rule object: "..table.tostring(v))
      end
   end

   io.flush()
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

function on_event(evt_, rule_id)

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

   return rule.rule, rule.priority, rule.output
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



