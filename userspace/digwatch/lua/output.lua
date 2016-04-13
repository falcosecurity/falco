local mod = {}

levels = {"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}

function mod.stdout(evt, level, format)
   format = "%evt.time: "..levels[level+1].." "..format
   formatter = digwatch.formatter(format)
   msg = digwatch.format_event(evt, formatter)
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

function mod.file(evt, level, format, options)
   format = "%evt.time: "..levels[level+1].." "..format
   formatter = digwatch.formatter(format)
   msg = digwatch.format_event(evt, formatter)

   file = io.open(options.filename, "a+")
   file:write(msg, "\n")
   file:close()
end

function mod.syslog(evt, level, format)

   formatter = digwatch.formatter(format)
   msg = digwatch.format_event(evt, formatter)
   digwatch.syslog(level, msg)
end

return mod
