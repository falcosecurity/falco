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

function mod.stdout(priority, priority_num, buffered, msg)
   if buffered == 0 then
      io.stdout:setvbuf 'no'
   end
   print (msg)
end

function mod.stdout_cleanup()
   io.stdout:flush()
end

function mod.file_validate(options)
   if (not type(options.filename) == 'string') then
      error("File output needs to be configured with a valid filename")
   end

   local file, err = io.open(options.filename, "a+")
   if file == nil then
      error("Error with file output: "..err)
   end
   file:close()

end

function mod.file(priority, priority_num, buffered, msg, options)
   if options.keep_alive == "true" then
      if ffile == nil then
          ffile = io.open(options.filename, "a+")
          if buffered == 0 then
              ffile:setvbuf 'no'
          end
      end
   else
      ffile = io.open(options.filename, "a+")
   end

   ffile:write(msg, "\n")

   if options.keep_alive == nil or
          options.keep_alive ~= "true" then
      ffile:close()
      ffile = nil
   end
end

function mod.file_cleanup()
   if ffile ~= nil then
      ffile:flush()
      ffile:close()
      ffile = nil
   end
end

function mod.syslog(priority, priority_num, buffered, msg, options)
   falco.syslog(priority_num, msg)
end

function mod.syslog_cleanup()
end

function mod.program(priority, priority_num, buffered, msg, options)
   -- XXX Ideally we'd check that the program ran
   -- successfully. However, the luajit we're using returns true even
   -- when the shell can't run the program.

   -- Note: options are all strings
   if options.keep_alive == "true" then
      if pfile == nil then
          pfile = io.popen(options.program, "w")
          if buffered == 0 then
              pfile:setvbuf 'no'
          end
      end
   else
      pfile = io.popen(options.program, "w")
   end

   pfile:write(msg, "\n")

   if options.keep_alive == nil or
          options.keep_alive ~= "true" then
      pfile:close()
      pfile = nil
   end
end

function mod.program_cleanup()
   if pfile ~= nil then
      pfile:flush()
      pfile:close()
      pfile = nil
   end
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
      o.output(priority, priority_num, o.buffered, msg, o.config)
   end
end

function output_cleanup()
   formats.free_formatters()
   for index,o in ipairs(outputs) do
      o.cleanup()
   end
end

function add_output(output_name, buffered, config)
   if not (type(mod[output_name]) == 'function') then
      error("rule_loader.add_output(): invalid output_name: "..output_name)
   end

   -- outputs can optionally define a validation function so that we don't
   -- find out at runtime (when an event finally matches a rule!) that the config is invalid
   if (type(mod[output_name.."_validate"]) == 'function') then
     mod[output_name.."_validate"](config)
   end

   table.insert(outputs, {output = mod[output_name],
			  cleanup = mod[output_name.."_cleanup"],
			  buffered=buffered, config=config})
end

return mod
