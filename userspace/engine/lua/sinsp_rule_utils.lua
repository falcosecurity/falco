-- Copyright (C) 2018 Draios inc.
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
--

local parser = require("parser")
local sinsp_rule_utils = {}

function sinsp_rule_utils.check_for_ignored_syscalls_events(ast, filter_type, source)

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

-- Examine the ast and find the event types/syscalls for which the
-- rule should run. All evt.type references are added as event types
-- up until the first "!=" binary operator or unary not operator. If
-- no event type checks are found afterward in the rule, the rule is
-- considered optimized and is associated with the event type(s).
--
-- Otherwise, the rule is associated with a 'catchall' category and is
-- run for all event types/syscalls. (Also, a warning is printed).
--

function sinsp_rule_utils.get_evttypes_syscalls(name, ast, source, warn_evttypes, verbose)

   local evttypes = {}
   local syscallnums = {}
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

                     -- The event must be a known event
                     if events[v.value] == nil and syscalls[v.value] == nil then
                        error("Unknown event/syscall \""..v.value.."\" in filter: "..source)
                     end

		     evtnames[v.value] = 1
		     if events[v.value] ~= nil then
			for id in string.gmatch(events[v.value], "%S+") do
			   evttypes[id] = 1
			end
		     end

		     if syscalls[v.value] ~= nil then
			for id in string.gmatch(syscalls[v.value], "%S+") do
			   syscallnums[id] = 1
			end
		     end
		  end
	       end
	    else
	       if node.right.type == "BareString" then

		  -- The event must be a known event
		  if events[node.right.value] == nil and syscalls[node.right.value] == nil then
		     error("Unknown event/syscall \""..node.right.value.."\" in filter: "..source)
		  end

		  evtnames[node.right.value] = 1
		  if events[node.right.value] ~= nil then
		     for id in string.gmatch(events[node.right.value], "%S+") do
			evttypes[id] = 1
		     end
		  end

		  if syscalls[node.right.value] ~= nil then
		     for id in string.gmatch(syscalls[node.right.value], "%S+") do
			syscallnums[id] = 1
		     end
		  end
	       end
	    end
	 end
      end
   end

   parser.traverse_ast(ast.filter.value, {BinaryRelOp=1, UnaryBoolOp=1} , cb)

   if not found_event then
      if warn_evttypes == true then
	 io.stderr:write("Rule "..name..": warning (no-evttype):\n")
	 io.stderr:write(source.."\n")
	 io.stderr:write("         did not contain any evt.type restriction, meaning it will run for all event types.\n")
	 io.stderr:write("         This has a significant performance penalty. Consider adding an evt.type restriction if possible.\n")
      end
      evttypes = {}
      syscallnums = {}
      evtnames = {}
   end

   if found_event_after_not then
      if warn_evttypes == true then
	 io.stderr:write("Rule "..name..": warning (trailing-evttype):\n")
	 io.stderr:write(source.."\n")
	 io.stderr:write("         does not have all evt.type restrictions at the beginning of the condition,\n")
	 io.stderr:write("         or uses a negative match (i.e. \"not\"/\"!=\") for some evt.type restriction.\n")
	 io.stderr:write("         This has a performance penalty, as the rule can not be limited to specific event types.\n")
	 io.stderr:write("         Consider moving all evt.type restrictions to the beginning of the rule and/or\n")
	 io.stderr:write("         replacing negative matches with positive matches if possible.\n")
      end
      evttypes = {}
      syscallnums = {}
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

   if verbose then
      io.stderr:write("Event types/Syscalls for rule "..name..": "..table.concat(evtnames_only, ",").."\n")
   end

   return evttypes, syscallnums
end

return sinsp_rule_utils
