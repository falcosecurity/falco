local mod = {}

function mod.syslog(evt, level, format)
   nixio = require("nixio")
   formatter = digwatch.formatter(format)
   msg = digwatch.format_event(evt, formatter)
   nixio.syslog(level, msg)
end


local first_sequence_state = {}

function mod.first_sequence(evt, fieldname, key, format)
   local field_value = digwatch.field(evt, fieldname)
   local now = os.time()

   if first_sequence_state[key] == nil then
      first_sequence_state[key] = {}
   end

   if first_sequence_state[key][field_value] == nil or
   now - first_sequence_state[key][field_value] > 5 then
      formatter = digwatch.formatter(format)
      msg = digwatch.format_event(evt, formatter)
      print (msg)
   end
   first_sequence_state[key][field_value] = now
end

return mod
