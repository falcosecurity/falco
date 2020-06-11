--[[
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

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

local pairs = pairs
local tostring = tostring
local setmetatable = setmetatable
local schar = string.char

local ansiterminal = {}

local colors = {
    -- attributes
    reset = 0,
    clear = 0,
    bright = 1,
    dim = 2,
    underscore = 4,
    blink = 5,
    reverse = 7,
    hidden = 8,

    -- foreground
    black = 30,
    red = 31,
    green = 32,
    yellow = 33,
    blue = 34,
    magenta = 35,
    cyan = 36,
    white = 37,

    -- background
    onblack = 40,
    onred = 41,
    ongreen = 42,
    onyellow = 43,
    onblue = 44,
    onmagenta = 45,
    oncyan = 46,
    onwhite = 47,
}

local function makecolor(name, value)
	ansiterminal[name] = schar(27) .. '[' .. tostring(value) .. 'm'
end

function ansiterminal.enable_color(enable_colors)
    if enable_colors == true then
        for c, v in pairs(colors) do
            makecolor(c, v)
        end
    else
        for name, v in pairs(colors) do
            ansiterminal[name] = ""
        end
    end
end

function ansiterminal.clearscreen()
    io.write(schar(27) .. '[' .. "2J")
end

function ansiterminal.moveto(x, y)
    io.write(schar(27) .. '[' .. tostring(x) .. ";" .. tostring(y) .. 'H')
end

function ansiterminal.moveup(n)
    io.write(schar(27) .. '[' .. tostring(n) .. 'F')
end

function ansiterminal.clearline()
    io.write(schar(27) .. '[' .. "2K")
end

function ansiterminal.hidecursor()
    io.write(schar(27) .. '[' .. "?25l")
end

function ansiterminal.showcursor()
    io.write(schar(27) .. '[' .. "?25h")
end

function ansiterminal.setfgcol(color)
    io.write(schar(27) .. '[' .. "38;5;" .. color .. "m")
end

function ansiterminal.setbgcol(color)
    io.write(schar(27) .. '[' .. "48;5;" .. color .. "m")
end

return ansiterminal
