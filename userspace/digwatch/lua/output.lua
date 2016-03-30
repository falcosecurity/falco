local mod = {}

function mod.syslog(evt, level, format)
   nixio = require("nixio")
   format = "%evt.time: "..format
   formatter = digwatch.formatter(format)
   msg = digwatch.format_event(evt, formatter)
   nixio.syslog(level, msg)
end

return mod
