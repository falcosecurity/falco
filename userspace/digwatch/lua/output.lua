local mod = {}

function mod.stdout(evt, level, format)
   format = "%evt.time: "..level.." "..format
   formatter = digwatch.formatter(format)
   msg = digwatch.format_event(evt, formatter)
   print (msg)
end

function mod.syslog(evt, level, format)
   nixio = require("nixio")
   formatter = digwatch.formatter(format)
   msg = digwatch.format_event(evt, formatter)
   nixio.syslog(level, msg)
end

return mod
