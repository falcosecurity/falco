#!/usr/bin/env bash
#
# Copyright (C) 2019 The Falco Authors.
#
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
#

set -ex

PREFIX=$1

if [ -z "$PREFIX" ]; then
    PREFIX=.
fi

mkdir -p $PREFIX

gcc -O2 -fPIC -I"$LUA_INCLUDE" -c lpcap.c -o $PREFIX/lpcap.o
gcc -O2 -fPIC -I"$LUA_INCLUDE" -c lpcode.c -o $PREFIX/lpcode.o
gcc -O2 -fPIC -I"$LUA_INCLUDE" -c lpprint.c -o $PREFIX/lpprint.o
gcc -O2 -fPIC -I"$LUA_INCLUDE" -c lptree.c -o $PREFIX/lptree.o
gcc -O2 -fPIC -I"$LUA_INCLUDE" -c lpvm.c -o $PREFIX/lpvm.o


# For building lpeg.so, which we don't need now that we're statically linking lpeg.a into falco
#gcc -shared -o lpeg.so -L/usr/local/lib lpcap.o lpcode.o lpprint.o lptree.o lpvm.o
#gcc -shared -o lpeg.so -L/usr/local/lib lpcap.o lpcode.o lpprint.o lptree.o lpvm.o

pushd $PREFIX
/usr/bin/ar cr lpeg.a lpcap.o lpcode.o lpprint.o lptree.o lpvm.o
/usr/bin/ranlib lpeg.a
popd

chmod ug+w re.lua
