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
--

local parser = require "parser"

if #arg ~= 1 then
    print("Usage: test.lua <string>")
    os.exit(1)
end

local macros = {}
local ast

local function doit(line)
   ast = parser.parse_filter(line)

   if not ast then
      print("error", error_msg)
      os.exit(1)
   end

end
for str in string.gmatch(arg[1], "([^;]+)") do
   doit(str)
end

if (ast and ast.type) then
   parser.print_ast(ast)
end

os.exit(0)

