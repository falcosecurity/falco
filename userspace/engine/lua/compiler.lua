-- Copyright (C) 2016-2018 Draios Inc dba Sysdig.
--
-- This file is part of falco.
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

local parser = require("parser")
local compiler = {}

compiler.trim = parser.trim

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
	    return false, "Undefined macro '".. ast.value.value .. "' used in filter."
         end
	 defs[ast.value.value].used = true
         ast.value = copy_ast_obj(defs[ast.value.value].ast)
         changed = true
	 return true, changed
      end
      return expand_macros(ast.value, defs, changed)

   elseif ast.type == "BinaryBoolOp" then

      if (ast.left.type == "Macro") then
         if (defs[ast.left.value] == nil) then
	    return false, "Undefined macro '".. ast.left.value .. "' used in filter."
         end
	 defs[ast.left.value].used = true
         ast.left = copy_ast_obj(defs[ast.left.value].ast)
         changed = true
      end

      if (ast.right.type == "Macro") then
         if (defs[ast.right.value] == nil) then
	    return false, "Undefined macro ".. ast.right.value .. " used in filter."
         end
	 defs[ast.right.value].used = true
         ast.right = copy_ast_obj(defs[ast.right.value].ast)
         changed = true
      end

      local status, changed_left = expand_macros(ast.left, defs, false)
      if status == false then
	 return false, changed_left
      end
      local status, changed_right = expand_macros(ast.right, defs, false)
      if status == false then
	 return false, changed_right
      end
      return true, changed or changed_left or changed_right

   elseif ast.type == "UnaryBoolOp" then
      if (ast.argument.type == "Macro") then
         if (defs[ast.argument.value] == nil) then
	    return false, "Undefined macro ".. ast.argument.value .. " used in filter."
         end
	 defs[ast.argument.value].used = true
         ast.argument = copy_ast_obj(defs[ast.argument.value].ast)
         changed = true
      end
      return expand_macros(ast.argument, defs, changed)
   end
   return true, changed
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

function get_filters(ast)

   local filters = {}

   function cb(node)
      if node.type == "FieldName" then
	 filters[node.value] = 1
      end
   end

   parser.traverse_ast(ast.filter.value, {FieldName=1} , cb)

   return filters
end

function compiler.expand_lists_in(source, list_defs)

   for name, def in pairs(list_defs) do

      local bpos = string.find(source, name, 1, true)

      while bpos ~= nil do
	 def.used = true

	 local epos = bpos + string.len(name)

	 -- The characters surrounding the name must be delimiters of beginning/end of string
	 if (bpos == 1 or string.match(string.sub(source, bpos-1, bpos-1), "[%s(),=]")) and (epos > string.len(source) or string.match(string.sub(source, epos, epos), "[%s(),=]")) then
	    new_source = ""

	    if bpos > 1 then
	       new_source = new_source..string.sub(source, 1, bpos-1)
	    end

	    sub = table.concat(def.items, ", ")

	    new_source = new_source..sub

	    if epos <= string.len(source) then
	       new_source = new_source..string.sub(source, epos, string.len(source))
	    end

	    source = new_source
	    bpos = bpos + (string.len(sub)-string.len(name))
	 end

	 bpos = string.find(source, name, bpos+1, true)
      end
   end

   return source
end

function compiler.compile_macro(line, macro_defs, list_defs)

   line = compiler.expand_lists_in(line, list_defs)

   local ast, error_msg = parser.parse_filter(line)

   if (error_msg) then
      msg = "Compilation error when compiling \""..line.."\": ".. error_msg
      return false, msg
   end

   -- Simply as a validation step, try to expand all macros in this
   -- macro's condition. This changes the ast, so we make a copy
   -- first.
   local ast_copy = copy_ast_obj(ast)

   if (ast.type == "Rule") then
      -- Line is a filter, so expand macro references
      repeat
	 status, expanded = expand_macros(ast_copy, macro_defs, false)
	 if status == false then
	    msg = "Compilation error when compiling \""..line.."\": ".. expanded
	    return false, msg
	 end
      until expanded == false

   else
      return false, "Unexpected top-level AST type: "..ast.type
   end

   return true, ast
end

--[[
   Parses a single filter, then expands macros using passed-in table of definitions. Returns resulting AST.
--]]
function compiler.compile_filter(name, source, macro_defs, list_defs)

   source = compiler.expand_lists_in(source, list_defs)

   local ast, error_msg = parser.parse_filter(source)

   if (error_msg) then
      msg = "Compilation error when compiling \""..source.."\": "..error_msg
      return false, msg
   end

   if (ast.type == "Rule") then
      -- Line is a filter, so expand macro references
      repeat
	 status, expanded  = expand_macros(ast, macro_defs, false)
	 if status == false then
	    return false, expanded
	 end
      until expanded == false

   else
      return false, "Unexpected top-level AST type: "..ast.type
   end

   filters = get_filters(ast)

   return true, ast, filters
end


return compiler
