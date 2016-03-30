local mod = {}

levels = {"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}

function mod.stdout(evt, level, format)
   format = "%evt.time: "..levels[level+1].." "..format
   formatter = digwatch.formatter(format)
   msg = digwatch.format_event(evt, formatter)
   print (msg)
end

function mod.syslog(evt, level, format)
   -- https://neopallium.github.io/nixio/modules/nixio.html#nixio.syslog
   levels = {"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

   nixio = require("nixio")
   formatter = digwatch.formatter(format)
   msg = digwatch.format_event(evt, formatter)
   nixio.syslog(levels[level+1], msg)
end

return mod
