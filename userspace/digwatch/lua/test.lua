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

if not (state.ast == nil) then -- can be nil if only macros
   compiler.parser.print_ast(state.ast)
end

os.exit(0)

