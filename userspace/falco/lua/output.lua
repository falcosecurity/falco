local mod = {}

levels = {"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}

mod.levels = levels

local outputs = {}

function mod.stdout(level, msg)
   print (msg)
end

function mod.file_validate(options)
   if (not type(options.filename) == 'string') then
      error("File output needs to be configured with a valid filename")
   end

   file, err = io.open(options.filename, "a+")
   if file == nil then
      error("Error with file output: "..err)
   end
   file:close()

end

function mod.file(level, msg, options)
   file = io.open(options.filename, "a+")
   file:write(msg, "\n")
   file:close()
end

function mod.syslog(level, msg, options)
   falco.syslog(level, msg)
end

function mod.program(level, msg, options)
   -- XXX Ideally we'd check that the program ran
   -- successfully. However, the luajit we're using returns true even
   -- when the shell can't run the program.

   file = io.popen(options.program, "w")

   file:write(msg, "\n")
   file:close()
end

local function level_of(s)
   s = string.lower(s)
   for i,v in ipairs(levels) do
      if (string.find(string.lower(v), "^"..s)) then
	 return i - 1 -- (syslog levels start at 0, lua indices start at 1)
      end
   end
   error("Invalid severity level: "..s)
end

function output_event(event, rule, priority, format)
   local level = level_of(priority)
   format = "*%evt.time: "..levels[level+1].." "..format
   formatter = falco.formatter(format)
   msg = falco.format_event(event, rule, levels[level+1], formatter)

   for index,o in ipairs(outputs) do
      o.output(level, msg, o.config)
   end

   falco.free_formatter(formatter)
end

function add_output(output_name, config)
   if not (type(mod[output_name]) == 'function') then
      error("rule_loader.add_output(): invalid output_name: "..output_name)
   end

   -- outputs can optionally define a validation function so that we don't
   -- find out at runtime (when an event finally matches a rule!) that the config is invalid
   if (type(mod[output_name.."_validate"]) == 'function') then
     mod[output_name.."_validate"](config)
   end

   table.insert(outputs, {output = mod[output_name], config=config})
end

return mod
