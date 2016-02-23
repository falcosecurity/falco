local compiler = require "compiler"

if #arg ~= 1 then
    print("Usage: test.lua <string>")
    os.exit(1)
end

local macros = {}
local ast

local function doit(line)
   ast = compiler.compile_line(line, macros)

   if not ast then
      print("error", error_msg)
      os.exit(1)
   end

end
for str in string.gmatch(arg[1], "([^;]+)") do
   doit(str)
end

if not (ast) then
   compiler.parser.print_ast(ast)
end

os.exit(0)

