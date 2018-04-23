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

function mod.stdout(priority, priority_num, msg, options)
   if options.buffered == 0 then
      io.stdout:setvbuf 'no'
   end
   print (msg)
end

function mod.stdout_cleanup()
   io.stdout:flush()
end

-- Note: not actually closing/reopening stdout
function mod.stdout_reopen(options)
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

function mod.file_open(options)
   if ffile == nil then
      ffile = io.open(options.filename, "a+")
      if options.buffered == 0 then
	 ffile:setvbuf 'no'
      end
   end
end

function mod.file(priority, priority_num, msg, options)
   if options.keep_alive == "true" then
      mod.file_open(options)
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

function mod.file_reopen(options)
   if options.keep_alive == "true" then
      mod.file_cleanup()
      mod.file_open(options)
   end
end

function mod.syslog(priority, priority_num, msg, options)
   falco.syslog(priority_num, msg)
end

function mod.syslog_cleanup()
end

function mod.syslog_reopen()
end

function mod.program_open(options)
   if pfile == nil then
      pfile = io.popen(options.program, "w")
      if options.buffered == 0 then
	 pfile:setvbuf 'no'
      end
   end
end

function mod.program(priority, priority_num, msg, options)
   -- XXX Ideally we'd check that the program ran
   -- successfully. However, the luajit we're using returns true even
   -- when the shell can't run the program.

   -- Note: options are all strings
   if options.keep_alive == "true" then
      mod.program_open(options)
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

function mod.program_reopen(options)
   if options.keep_alive == "true" then
      mod.program_cleanup()
      mod.program_open(options)
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
      o.output(priority, priority_num, msg, o.options)
   end
end

function output_cleanup()
   formats.free_formatters()
   for index,o in ipairs(outputs) do
      o.cleanup()
   end
end

function output_reopen()
   for index,o in ipairs(outputs) do
      o.reopen(o.options)
   end
end

function add_output(output_name, buffered, options)
   if not (type(mod[output_name]) == 'function') then
      error("rule_loader.add_output(): invalid output_name: "..output_name)
   end

   -- outputs can optionally define a validation function so that we don't
   -- find out at runtime (when an event finally matches a rule!) that the options are invalid
   if (type(mod[output_name.."_validate"]) == 'function') then
     mod[output_name.."_validate"](options)
   end

   if options == nil then
      options = {}
   end

   options.buffered = buffered

   table.insert(outputs, {output = mod[output_name],
			  cleanup = mod[output_name.."_cleanup"],
			  reopen = mod[output_name.."_reopen"],
			  options=options})
end

return mod
