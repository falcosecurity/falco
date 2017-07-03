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

local parser = require("parser")
local compiler = {}

compiler.verbose = false
compiler.all_events = false

function compiler.set_verbose(verbose)
   compiler.verbose = verbose
   parser.set_verbose(verbose)
end

function compiler.set_all_events(all_events)
   compiler.all_events = all_events
end

function map(f, arr)
   local res = {}
   for i,v in ipairs(arr) do
      res[i] = f(v)
   end
   return res
end

function foldr(f, acc, arr)
   for i,v in pairs(arr) do
      acc = f(acc, v)
   end
   return acc
end

--[[

   Given a map of macro definitions, traverse AST and replace macro references
   with their definitions.

   The AST is changed in-place.

   The return value is a boolean which is true if any macro was
   substitued. This allows a caller to re-traverse until no more macros are
   found, a simple strategy for recursive resoltuions (e.g. when a macro
   definition uses another macro).

--]]

function copy_ast_obj(obj)
   if type(obj) ~= 'table' then return obj end
   local res = {}
   for k, v in pairs(obj) do res[copy_ast_obj(k)] = copy_ast_obj(v) end
   return res
end

function expand_macros(ast, defs, changed)

   if (ast.type == "Rule") then
      return expand_macros(ast.filter, defs, changed)
   elseif ast.type == "Filter" then
      if (ast.value.type == "Macro") then
         if (defs[ast.value.value] == nil) then
            error("Undefined macro '".. ast.value.value .. "' used in filter.")
         end
         ast.value = copy_ast_obj(defs[ast.value.value])
         changed = true
	 return changed
      end
      return expand_macros(ast.value, defs, changed)

   elseif ast.type == "BinaryBoolOp" then

      if (ast.left.type == "Macro") then
         if (defs[ast.left.value] == nil) then
            error("Undefined macro '".. ast.left.value .. "' used in filter.")
         end
         ast.left = copy_ast_obj(defs[ast.left.value])
         changed = true
      end

      if (ast.right.type == "Macro") then
         if (defs[ast.right.value] == nil) then
            error("Undefined macro ".. ast.right.value .. " used in filter.")
         end
         ast.right = copy_ast_obj(defs[ast.right.value])
         changed = true
      end

      local changed_left = expand_macros(ast.left, defs, false)
      local changed_right = expand_macros(ast.right, defs, false)
      return changed or changed_left or changed_right

   elseif ast.type == "UnaryBoolOp" then
      if (ast.argument.type == "Macro") then
         if (defs[ast.argument.value] == nil) then
            error("Undefined macro ".. ast.argument.value .. " used in filter.")
         end
         ast.argument = copy_ast_obj(defs[ast.argument.value])
         changed = true
      end
      return expand_macros(ast.argument, defs, changed)
   end
   return changed
end

function get_macros(ast, set)
   if (ast.type == "Macro") then
      set[ast.value] = true
      return set
   end

   if ast.type == "Filter" then
      return get_macros(ast.value, set)
   end

   if ast.type == "BinaryBoolOp" then
      local left = get_macros(ast.left, {})
      local right = get_macros(ast.right, {})

      for m, _ in pairs(left) do set[m] = true end
      for m, _ in pairs(right) do set[m] = true end

      return set
   end
   if ast.type == "UnaryBoolOp" then
      return get_macros(ast.argument, set)
   end
   return set
end

function check_for_ignored_syscalls_events(ast, filter_type, source)

   function check_syscall(val)
      if ignored_syscalls[val] then
	 error("Ignored syscall \""..val.."\" in "..filter_type..": "..source)
      end

   end

   function check_event(val)
      if ignored_events[val] then
	 error("Ignored event \""..val.."\" in "..filter_type..": "..source)
      end
   end

   function cb(node)
      if node.left.type == "FieldName" and
	 (node.left.value == "evt.type" or
	  node.left.value == "syscall.type") then

	    if node.operator == "in" or node.operator == "pmatch" then
	       for i, v in ipairs(node.right.elements) do
		  if v.type == "BareString" then
		     if node.left.value == "evt.type" then
			check_event(v.value)
		     else
			check_syscall(v.value)
		     end
		  end
	       end
	    else
	       if node.right.type == "BareString" then
		  if node.left.value == "evt.type" then
		     check_event(node.right.value)
		  else
		     check_syscall(node.right.value)
		  end
	       end
	    end
      end
   end

   parser.traverse_ast(ast, {BinaryRelOp=1}, cb)
end

-- Examine the ast and find the event types for which the rule should
-- run. All evt.type references are added as event types up until the
-- first "!=" binary operator or unary not operator. If no event type
-- checks are found afterward in the rule, the rule is considered
-- optimized and is associated with the event type(s).
--
-- Otherwise, the rule is associated with a 'catchall' category and is
-- run for all event types. (Also, a warning is printed).
--

function get_evttypes(name, ast, source)

   local evttypes = {}
   local evtnames = {}
   local found_event = false
   local found_not = false
   local found_event_after_not = false

   function cb(node)
     if node.type == "UnaryBoolOp" then
	if node.operator == "not" then
	   found_not = true
	end
     else
	 if node.operator == "!=" then
	    found_not = true
	 end
	 if node.left.type == "FieldName" and node.left.value == "evt.type" then
	    found_event = true
	    if found_not then
	       found_event_after_not = true
	    end
	    if node.operator == "in" or node.operator == "pmatch" then
	       for i, v in ipairs(node.right.elements) do
		  if v.type == "BareString" then
		     evtnames[v.value] = 1
		     for id in string.gmatch(events[v.value], "%S+") do
			evttypes[id] = 1
		     end
		  end
	       end
	    else
	       if node.right.type == "BareString" then
		  evtnames[node.right.value] = 1
		  for id in string.gmatch(events[node.right.value], "%S+") do
		     evttypes[id] = 1
		  end
	       end
	    end
	 end
      end
   end

   parser.traverse_ast(ast.filter.value, {BinaryRelOp=1, UnaryBoolOp=1} , cb)

   if not found_event then
      io.stderr:write("Rule "..name..": warning (no-evttype):\n")
      io.stderr:write(source.."\n")
      io.stderr:write("         did not contain any evt.type restriction, meaning it will run for all event types.\n")
      io.stderr:write("         This has a significant performance penalty. Consider adding an evt.type restriction if possible.\n")
      evttypes = {}
      evtnames = {}
   end

   if found_event_after_not then
      io.stderr:write("Rule "..name..": warning (trailing-evttype):\n")
      io.stderr:write(source.."\n")
      io.stderr:write("         does not have all evt.type restrictions at the beginning of the condition,\n")
      io.stderr:write("         or uses a negative match (i.e. \"not\"/\"!=\") for some evt.type restriction.\n")
      io.stderr:write("         This has a performance penalty, as the rule can not be limited to specific event types.\n")
      io.stderr:write("         Consider moving all evt.type restrictions to the beginning of the rule and/or\n")
      io.stderr:write("         replacing negative matches with positive matches if possible.\n")
      evttypes = {}
      evtnames = {}
   end

   evtnames_only = {}
   local num_evtnames = 0
   for name, dummy in pairs(evtnames) do
      table.insert(evtnames_only, name)
      num_evtnames = num_evtnames + 1
   end

   if num_evtnames == 0 then
      table.insert(evtnames_only, "all")
   end

   table.sort(evtnames_only)

   if compiler.verbose then
      io.stderr:write("Event types for rule "..name..": "..table.concat(evtnames_only, ",").."\n")
   end

   return evttypes
end

function compiler.compile_macro(line, macro_defs, list_defs)

   for name, items in pairs(list_defs) do
      line = string.gsub(line, name, table.concat(items, ", "))
   end

   local ast, error_msg = parser.parse_filter(line)

   if (error_msg) then
      msg = "Compilation error when compiling \""..line.."\": ".. error_msg
      error(msg)
   end

   -- Traverse the ast looking for events/syscalls in the ignored
   -- syscalls table. If any are found, return an error.
   if not compiler.all_events then
      check_for_ignored_syscalls_events(ast, 'macro', line)
   end

   -- Simply as a validation step, try to expand all macros in this
   -- macro's condition. This changes the ast, so we make a copy
   -- first.
   local ast_copy = copy_ast_obj(ast)

   if (ast.type == "Rule") then
      -- Line is a filter, so expand macro references
      repeat
	 expanded  = expand_macros(ast_copy, macro_defs, false)
      until expanded == false

   else
      error("Unexpected top-level AST type: "..ast.type)
   end

   return ast
end

--[[
   Parses a single filter, then expands macros using passed-in table of definitions. Returns resulting AST.
--]]
function compiler.compile_filter(name, source, macro_defs, list_defs)

   for name, items in pairs(list_defs) do
      local begin_name_pat = "^("..name..")([%s(),=])"
      local mid_name_pat = "([%s(),=])("..name..")([%s(),=])"
      local end_name_pat = "([%s(),=])("..name..")$"
      source = string.gsub(source, begin_name_pat, table.concat(items, ", ").."%2")
      source = string.gsub(source, mid_name_pat, "%1"..table.concat(items, ", ").."%3")
      source = string.gsub(source, end_name_pat, "%1"..table.concat(items, ", "))
   end

   local ast, error_msg = parser.parse_filter(source)

   if (error_msg) then
      msg = "Compilation error when compiling \""..source.."\": "..error_msg
      error(msg)
   end

   -- Traverse the ast looking for events/syscalls in the ignored
   -- syscalls table. If any are found, return an error.
   if not compiler.all_events then
      check_for_ignored_syscalls_events(ast, 'rule', source)
   end

   if (ast.type == "Rule") then
      -- Line is a filter, so expand macro references
      repeat
	 expanded  = expand_macros(ast, macro_defs, false)
      until expanded == false

   else
      error("Unexpected top-level AST type: "..ast.type)
   end

   evttypes = get_evttypes(name, ast, source)

   return ast, evttypes
end


return compiler
