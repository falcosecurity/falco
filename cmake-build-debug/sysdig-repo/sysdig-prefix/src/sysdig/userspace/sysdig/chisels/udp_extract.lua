--[[
Copyright (C) 2018 Draios inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]
local OUTPUT_DIR_NAME = "./udp_dump_files"

description = "This chisel parses a trace file, identifies file descriptors carrying UDP network traffic (DNS excluded) and dumps the content of each FD into a different file in the " .. OUTPUT_DIR_NAME .. " directory. Files are named after the UDP tuple they contain.";
short_description = "extract data from UDP streams to files.";
category = "I/O";

args = {}

files = {}

function mkdir(dirname)
	os.execute('mkdir ' .. dirname .. " 2> /dev/null")
	os.execute('md ' .. dirname .. " 2> nul")
end

function on_init()
	fbuf = chisel.request_field("evt.rawarg.data")
	fres = chisel.request_field("evt.rawarg.res")
	ffdname = chisel.request_field("fd.name")
	ffdtype = chisel.request_field("fd.type")

	mkdir(OUTPUT_DIR_NAME)

	sysdig.set_snaplen(16384)
	chisel.set_filter("evt.dir=< and evt.rawres>=0 and fd.l4proto=udp and evt.is_io=true")
	return true
end

function on_capture_start()
	if sysdig.is_live() then
		print("live capture not supported")
		return false
	end
	return true
end

function on_event()
	local buf = evt.field(fbuf)
	local etype = evt.get_type()
	local res = evt.field(fres)
	local fdname = evt.field(ffdname)
	local fdtype = evt.field(fdtype)
	local containername = evt.field(fcontainername)
	local is_io_read = evt.field(fis_io_read)
	local is_io_write = evt.field(fis_io_write)

	if not files[fdname] then
		file_name = OUTPUT_DIR_NAME .. "/" .. fdname
		file_name = string.gsub(file_name, ":", "_")
		file_name = string.gsub(file_name, ">", "-")
		files[fdname] = io.open(file_name, "w")
	end

	files[fdname]:write(buf)

	return true
end
