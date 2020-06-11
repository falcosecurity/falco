--[[
Copyright (C) 2013-2018 Draios Inc dba Sysdig.
Copyright (C) 2015 Brendan Gregg.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

--]]

-- Chisel description
description = "This visualizes the subsecond offset time of system call execution. This allows repetitive patterns to be identified, which are lost when averaging at a one second granularity. The Y axis (vertical) shows the passage of time. The X axis (horizontal) shows the passage of time within whole or fractions of a second. By default, the X axis range is 1000 milliseconds; this can be specified as an argument (try 100). Each bucket of the heat map, or spectrogram, is shown as a colored rectangle. The color shows how many syscalls fell into that time and subsecond offset range. It can be black (no calls), green (tens of calls/s), yellow (hundreds of calls/s) or red (Thousands of calls/s). Use this chisel in conjunction with filters to visualize latencies for certain processes, types of I/O activity, file systems, etc."
short_description = "Visualize subsecond offset execution time."
category = "CPU Usage"

-- Chisel argument list
args = {
	{
		name = "refresh_time",
		description = "chart refresh time in milliseconds",
		argtype = "int",
		optional = true
	},
}

require "common"
terminal = require "ansiterminal"
terminal.enable_color(true)

refresh_time = 1000 * 1000 * 1000
refresh_per_sec = 1 * 1000 * 1000 * 1000 / refresh_time
max_label_len = 0
frequencies = {}
colpalette = {22, 28, 64, 34, 2, 76, 46, 118, 154, 191, 227, 226, 11, 220, 209, 208, 202, 197, 9, 1}
charpalette = {" ", "░", "▒", "░"}

-- Argument initialization
function on_set_arg(name, val)
	if name == "refresh_time" then
		refresh_time = parse_numeric_input(val, name) * 1 * 1000 * 1000
		refresh_per_sec = 1 * 1000 * 1000 * 1000 / refresh_time
		return true
	end

	return false
end

-- Initialization callback
function on_init()
	is_tty = sysdig.is_tty()

	if not is_tty then
		print("This chisel only works on ANSI terminals. Aborting.")
		return false
	end

	tinfo = sysdig.get_terminal_info()
	w = tinfo.width
	h = tinfo.height
	max_label_len = string.len("|" .. (0.9 * refresh_time / 10000000) .. "ms")

	-- trace syscall entry
	chisel.set_filter("evt.dir=>")

	rawtime = chisel.request_field("evt.rawtime")

	terminal.hidecursor()

	print("Tracing syscalls... red (hot) == high frequency <-> green == low frequency.\n")

	return true
end

-- Final chisel initialization
function on_capture_start()
	chisel.set_interval_ns(refresh_time)
	return true
end

-- Event parsing callback
function on_event()
	local subsec = evt.field(rawtime)

	-- subsec is normalized to terminal column location
	subsec = math.floor((((subsec * 1000 / refresh_time) % 1000) / 1000) * w)

	if frequencies[subsec] == nil then
		frequencies[subsec] = 1
	else
		frequencies[subsec] = frequencies[subsec] + 1
	end

	return true
end

-- Calculate colors and character to be used
function mkcol(n)
	local col = math.log10(n * refresh_per_sec + 1) / math.log10(1.6)

	if col < 1 then
		col = 1
	elseif col > #colpalette then
		col = #colpalette
	end

	local low_col = math.floor(col)
	local high_col = math.ceil(col)
	local delta = col - low_col
	local ch = charpalette[math.floor(1 + delta * #charpalette)]

	-- If delta is > 75% we use 25% fill and flip fg and bg to fake a 75% filled block
	if delta > .75 then
		return colpalette[high_col], colpalette[low_col], ch
	else
		return colpalette[low_col], colpalette[high_col], ch
	end	
end

-- Periodic timeout callback
function on_interval(ts_s, ts_ns, delta)
	terminal.moveup(1)

	for x = 1, w do
		local fr = frequencies[x]
		local fg, bg, ch

		if fr == nil or fr == 0 then
			terminal.setbgcol(0)
			terminal.setbgcol(0)
			ch = " "
		else
			fg, bg, ch = mkcol(fr)
			terminal.setfgcol(fg)
			terminal.setbgcol(bg)
		end

		io.write(ch)
	end

	io.write(terminal.reset .. "\n")

	local x = 0
	while true do
		if x >= w then
			break
		end

		local curtime = math.floor(x * 10 / w)
		local prevtime = math.floor((x - 1) * 10 / w)

		if curtime ~= prevtime then
			if (x <= w - max_label_len) then
				local tstr = "|" .. (math.floor(10 * x / w) * refresh_time / 10000000) .. "ms"
				io.write(tstr)
				x = x + string.len(tstr)
			else
				io.write(" ")
				x = x + 1
			end
		else
			io.write(" ")
			x = x + 1
		end
	end

	io.write("\n")

	frequencies = {}

	return true
end

function on_capture_end(ts_s, ts_ns, delta)
	if is_tty then
		print(terminal.reset)
		terminal.showcursor()
	end

	return true
end

