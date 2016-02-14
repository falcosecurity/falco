local compiler = require "sysdig-parser"

if #arg ~= 1 then
    print("Usage: test.lua <string>")
    os.exit(1)
end

local state = compiler.init()

local ast, state, error_msg = compiler.compile_line(arg[1], state)
if not ast then
    os.exit(1)
end

os.exit(0)

