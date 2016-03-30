--[[
   Compile and install digwatch rules.

   This module exports functions that are called from digwatch c++-side to compile and install a set of rules.

--]]

local DEFAULT_OUTPUT_FORMAT = "%evt.time: %evt.num %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.args"

local compiler = require "compiler"

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

local state

--[[
   Sets up compiler state and returns it.

   It holds state such as macro definitions that must be kept across calls
   to the line-oriented compiler.
--]]
local function init()
   return {macros={}, filter_ast=nil, n_rules=0, outputs={}}
end


function set_output(output_ast)

   if(output_ast.type == "OutputFormat") then

      local format
      if output_ast.value==nil then
	 format = DEFAULT_OUTPUT_FORMAT
      else
	 format = output_ast.value
      end

      state.outputs[state.n_rules] = {format=format, level = output_ast.level}

   else
      error ("Unexpected type in set_output: ".. output_ast.type)
   end
end

function load_rule(r)
   if (state == nil) then
      state = init()
   end
   local line_ast = compiler.compile_line(r, state.macros)

   if (line_ast.type == nil) then -- blank line
      return
   elseif (line_ast.type == "MacroDef") then
      return
   elseif (not (line_ast.type == "Rule")) then
      error ("Unexpected type in load_rule: "..line_ast.type)
   end

   state.n_rules = state.n_rules + 1

   set_output(line_ast.output)

   -- Store the index of this formatter in each relational expression that
   -- this rule contains.
   -- This index will eventually be stamped in events passing this rule, and
   -- we'll use it later to determine which output to display when we get an
   -- event.
   mark_relational_nodes(line_ast.filter.value, state.n_rules)

   -- Rule ASTs are merged together into one big AST, with "OR" between each
   -- rule.
   if (state.filter_ast == nil) then
      state.filter_ast = line_ast.filter.value
   else
      state.filter_ast = { type = "BinaryBoolOp", operator = "or", left = state.filter_ast, right = line_ast.filter.value }
   end
end

function on_done()
   install_filter(state.filter_ast)
   io.flush()
end

local outputs = require('output')

function on_event(evt_, rule_id, output_name)
   if not (type(outputs[output_name]) == 'function') then
      error("rule_loader.on_event(): invalid output_name: ", output_name)
   end

   if state.outputs[rule_id] == nil then
      error ("rule_loader.on_event(): event with invalid rule_id: ", rule_id)
   end

   outputs[output_name](evt_, state.outputs[rule_id].level, state.outputs[rule_id].format)
end

