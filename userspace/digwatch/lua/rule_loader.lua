--[[
   Compile and install digwatch rules.

   This module exports functions that are called from digwatch c++-side to compile and install a set of rules.

--]]

local compiler = require "compiler"

local function mark_check_nodes(ast, index)
   local t = ast.type

   if t == "BinaryBoolOp" then
      mark_check_nodes(ast.left, index)
      mark_check_nodes(ast.right, index)

   elseif t == "UnaryBoolOp" then
      mark_check_nodes(ast.argument, index)

   elseif t == "BinaryRelOp" then
      ast.index = index

   elseif t == "UnaryRelOp"  then
      ast.index = index

   else
      error ("Unexpected type in install_filter: "..t)
   end
end

local function install_filter(node)
   local t = node.type

   if t == "BinaryBoolOp" then
      filter.nest() --io.write("(")
      install_filter(node.left)
      filter.bool_op(node.operator) --io.write(" "..node.operator.." ")
      install_filter(node.right)
      filter.unnest() --io.write(")")

   elseif t == "UnaryBoolOp" then
      filter.nest() --io.write("(")
      filter.bool_op(node.operator) -- io.write(" "..node.operator.." ")
      install_filter(node.argument)
      filter.unnest() -- io.write(")")

   elseif t == "BinaryRelOp" then
      filter.rel_expr(node.left.value, node.operator, node.right.value, node.index)
      -- io.write(node.left.value.." "..node.operator.." "..node.right.value)

   elseif t == "UnaryRelOp"  then
      filter.rel_expr(node.argument.value, node.operator, node.index)
      --io.write(node.argument.value.." "..node.operator)

   else
      error ("Unexpected type in install_filter: "..t)
   end
end


-- filter.rel_expr("proc.name",  "=", "cat")
-- filter.bool_op("and")
-- filter.nest()
-- filter.nest()
-- filter.rel_expr("fd.num",  "=", "1")
-- filter.bool_op("or")
-- filter.rel_expr("fd.num",  "=", "2")
-- filter.unnest()
-- filter.unnest()

local state

--[[
   Sets up compiler state and returns it.

   It holds state such as macro definitions that must be kept across calls
   to the line-oriented compiler.
--]]
local function init()
   return {macros={}, filter_ast=nil, n_rules=0}
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

   digwatch.set_formatter(state.n_rules, line_ast.output.value)
   mark_check_nodes(line_ast.filter.value, state.n_rules)

   state.n_rules = state.n_rules + 1

   if (state.filter_ast == nil) then
      state.filter_ast = line_ast.filter.value
   else
      state.filter_ast = { type = "BinaryBoolOp", operator = "or", left = state.filter_ast, right = line_ast.filter.value }
   end
end

function on_done()
   install_filter(state.filter_ast)
end
