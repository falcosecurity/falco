local mod = {}

levels = {"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}

mod.levels = levels

local outputs = {}

function mod.stdout(evt, rule, level, format)
   format = "*%evt.time: "..levels[level+1].." "..format
   formatter = falco.formatter(format)
   msg = falco.format_event(evt, rule, levels[level+1], formatter)
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

function mod.file(evt, rule, level, format, options)
   format = "%evt.time: "..levels[level+1].." "..format
   formatter = falco.formatter(format)
   msg = falco.format_event(evt, rule, levels[level+1], formatter)

   file = io.open(options.filename, "a+")
   file:write(msg, "\n")
   file:close()
end

function mod.syslog(evt, rule, level, format)

   formatter = falco.formatter(format)
   msg = falco.format_event(evt, rule, levels[level+1], formatter)
   falco.syslog(level, msg)
end

function mod.event(event, rule, level, format)
   for index,o in ipairs(outputs) do
      o.output(event, rule, level, format, o.config)
   end
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
