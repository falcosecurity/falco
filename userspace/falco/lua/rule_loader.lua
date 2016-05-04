--[[
   Compile and install falco rules.

   This module exports functions that are called from falco c++-side to compile and install a set of rules.

--]]

local DEFAULT_OUTPUT_FORMAT = "%evt.time: %evt.num %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.args"
local DEFAULT_PRIORITY = "WARNING"


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

local state = {macros={}, filter_ast=nil, n_rules=0, outputs={}}

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

      else -- filter

	 if (v['condition'] == nil) then
	    error ("Missing condition in rule")
	 end

	 if (v['output'] == nil) then
	    error ("Missing output in rule with condition"..v['condition'])
	 end

	 local filter_ast = compiler.compile_filter(v['condition'], state.macros)

	 if (filter_ast.type == "Rule") then
	    state.n_rules = state.n_rules + 1

	    state.outputs[state.n_rules] = {format=v['output'] or DEFAULT_OUTPUT_FORMAT,
					    level=priority(v['priority'] or DEFAULT_PRIORITY)}

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

local output_functions = require('output')
outputs = {}

function add_output(output_name, config)
   if not (type(output_functions[output_name]) == 'function') then
      error("rule_loader.add_output(): invalid output_name: "..output_name)
   end

   -- outputs can optionally define a validation function so that we don't
   -- find out at runtime (when an event finally matches a rule!) that the config is invalid
   if (type(output_functions[output_name.."_validate"]) == 'function') then
     output_functions[output_name.."_validate"](config)
   end

   table.insert(outputs, {output = output_functions[output_name], config=config})
end

function on_event(evt_, rule_id)

   if state.outputs[rule_id] == nil then
      error ("rule_loader.on_event(): event with invalid rule_id: ", rule_id)
   end

   for index,o in ipairs(outputs) do
      o.output(evt_, state.outputs[rule_id].level, state.outputs[rule_id].format, o.config)
   end

end

