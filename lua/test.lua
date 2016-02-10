local parser = require "sysdig-parser"

if #arg ~= 1 then
    print("Usage: test.lua <string>")
    os.exit(1)
end

local ast, error_msg = parser.parse(arg[1])
if not ast then
    os.exit(1)
end

os.exit(0)

