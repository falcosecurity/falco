# Copyright (C) 2016-2018 Draios Inc dba Sysdig.
#
# This file is part of falco.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/bin/bash

function error_exit_good
{
    echo "Error: '$1' did not compiler" 1>&2
    exit 1
}

function error_exit_bad
{
    echo "Error: incorrect filter '$1' compiler ok" 1>&2
    exit 1
}


function good
{
    lua5.1 test.lua "$1" 2> /dev/null || error_exit_good "$1"
}

function bad
{
    lua5.1 test.lua "$1" 2> /dev/null && error_exit_bad "$1"
}

# Filters
good "  a"
good "a and b"
good "#a and b; a and b"
good "#a and b; # ; ; a and b"
good "(a)"
good "(a and b)"
good "(a.a exists and b)"
good "(a.a exists) and (b)"
good "a.a exists and b"
good "a.a=1 or b.b=2 and c"
good "not (a)"
good "not (not (a))"
good "not (a.b=1)"
good "not (a.a exists)"
good "not a"
good "a.b = 1 and not a"
good "not not a"
good "(not not a)"
good "not a.b=1"
good "not a.a exists"
good "notz and a and b"
good "a.b = bla"
good "a.b = 'bla'"
good "a.b = not"
good "a.b contains bla"
good "a.b icontains 'bla'"
good "a.g in (1, 'a', b)"
good "a.g in ( 1 ,, , b)"
good "evt.dir=> and fd.name=*.log"
good "evt.dir=> and fd.name=/var/log/httpd.log"
good "a.g in (1, 'a', b.c)"
good "a.b = a.a"

good "evt.arg[0] contains /bin"
bad "evt.arg[a] contains /bin"
bad "evt.arg[] contains /bin"

bad "a.b = b = 1"
bad "(a.b = 1"


echo
echo "All tests passed."
exit 0
