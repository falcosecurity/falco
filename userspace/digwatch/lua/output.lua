local mod = {}

levels = {"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}

function mod.stdout(evt, level, format)
   format = "%evt.time: "..levels[level+1].." "..format
   formatter = digwatch.formatter(format)
   msg = digwatch.format_event(evt, formatter)
   print (msg)
end

function mod.syslog(evt, level, format)

   formatter = digwatch.formatter(format)
   msg = digwatch.format_event(evt, formatter)
   digwatch.syslog(level, msg)
end

return mod
