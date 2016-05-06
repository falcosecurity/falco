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

