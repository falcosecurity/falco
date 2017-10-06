--
-- Copyright (C) 2016 Draios inc.
--
-- This file is part of falco.
--
-- falco is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License version 2 as
-- published by the Free Software Foundation.
--
-- falco is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with falco.  If not, see <http://www.gnu.org/licenses/>.


local mod = {}

local outputs = {}

function mod.stdout(priority, priority_num, msg)
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

function mod.file(priority, priority_num, msg, options)
   file = io.open(options.filename, "a+")
   file:write(msg, "\n")
   file:close()
end

function mod.syslog(priority, priority_num, msg, options)
   falco.syslog(priority_num, msg)
end

function mod.program(priority, priority_num, msg, options)
   -- XXX Ideally we'd check that the program ran
   -- successfully. However, the luajit we're using returns true even
   -- when the shell can't run the program.

   file = io.popen(options.program, "w")

   file:write(msg, "\n")
   file:close()
end

function output_event(event, rule, priority, priority_num, format)
   -- If format starts with a *, remove it, as we're adding our own
   -- prefix here.
   if format:sub(1,1) == "*" then
      format = format:sub(2)
   end

   format = "*%evt.time: "..priority.." "..format

   msg = formats.format_event(event, rule, priority, format)

   for index,o in ipairs(outputs) do
      o.output(priority, priority_num, msg, o.config)
   end
end

function output_cleanup()
   formats.free_formatters()
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
