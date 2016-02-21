local compiler = require "compiler"

if #arg ~= 1 then
    print("Usage: test.lua <string>")
    os.exit(1)
end

local state = compiler.init()

local function doit(line)
   local ast = compiler.compile_line(line, state)

   if not ast then
      print("error", error_msg)
      os.exit(1)
   end

end
for str in string.gmatch(arg[1], "([^;]+)") do
   doit(str)
end

compiler.parser.print_ast(state.ast)

os.exit(0)

