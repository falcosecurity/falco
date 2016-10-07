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

