--[[
   Compile and install falco rules.

   This module exports functions that are called from falco c++-side to compile and install a set of rules.

--]]

local output = require('output')
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
      if (node.operator == "in") then
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

local function priority(s)
   valid_levels = {"emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"}
   s = string.lower(s)
   for i,v in ipairs(valid_levels) do
      if (string.find(v, "^"..s)) then
	 return i - 1 -- (syslog levels start at 0, lua indices start at 1)
      end
   end
   error("Invalid severity level: "..level)
end

-- Note that the rules_by_name and rules_by_idx refer to the same rule
-- object. The by_name index is used for things like describing rules,
-- and the by_idx index is used to map the relational node index back
-- to a rule.
local state = {macros={}, filter_ast=nil, rules_by_name={}, n_rules=0, rules_by_idx={}}

function load_rules(filename)

   local f = assert(io.open(filename, "r"))
   local s = f:read("*all")
   f:close()
   local rules = yaml.load(s)

   for i,v in ipairs(rules) do -- iterate over yaml list

      if (not (type(v) == "table")) then
	 error ("Unexpected element of type " ..type(v)..". Each element should be a yaml associative array.")
      end

      if (v['macro']) then
	 local ast = compiler.compile_macro(v['condition'])
	 state.macros[v['macro']] = ast.filter.value

      else -- rule

	 if (v['rule'] == nil) then
	    error ("Missing name in rule")
	 end

	 for i, field in ipairs({'condition', 'output', 'desc', 'priority'}) do
	    if (v[field] == nil) then
	       error ("Missing "..field.." in rule with name "..v['rule'])
	    end
	 end

	 -- Convert the priority as a string to a level now
	 v['level'] = priority(v['priority'])
	 state.rules_by_name[v['rule']] = v

	 local filter_ast = compiler.compile_filter(v['condition'], state.macros)

	 if (filter_ast.type == "Rule") then
	    state.n_rules = state.n_rules + 1

	    state.rules_by_idx[state.n_rules] = v

	    -- Store the index of this formatter in each relational expression that
	    -- this rule contains.
	    -- This index will eventually be stamped in events passing this rule, and
	    -- we'll use it later to determine which output to display when we get an
	    -- event.
	    mark_relational_nodes(filter_ast.filter.value, state.n_rules)

	    -- Rule ASTs are merged together into one big AST, with "OR" between each
	    -- rule.
	    if (state.filter_ast == nil) then
	       state.filter_ast = filter_ast.filter.value
	    else
	       state.filter_ast = { type = "BinaryBoolOp", operator = "or", left = state.filter_ast, right = filter_ast.filter.value }
	    end
	 else
	    error ("Unexpected type in load_rule: "..filter_ast.type)
	 end
      end
   end

   install_filter(state.filter_ast)
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

function on_event(evt_, rule_id)

   if state.rules_by_idx[rule_id] == nil then
      error ("rule_loader.on_event(): event with invalid rule_id: ", rule_id)
   end

   output.event(evt_, state.rules_by_idx[rule_id].level, state.rules_by_idx[rule_id].output)
end

