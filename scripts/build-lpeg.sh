#!/bin/sh

gcc -O2 -fPIC -I$LUA_INCLUDE -c lpcap.c -o lpcap.o
gcc -O2 -fPIC -I$LUA_INCLUDE -c lpcode.c -o lpcode.o
gcc -O2 -fPIC -I$LUA_INCLUDE -c lpprint.c -o lpprint.o
gcc -O2 -fPIC -I$LUA_INCLUDE -c lptree.c -o lptree.o
gcc -O2 -fPIC -I$LUA_INCLUDE -c lpvm.c -o lpvm.o
gcc -shared -o lpeg.so -L/usr/local/lib lpcap.o lpcode.o lpprint.o lptree.o lpvm.o

chmod ug+w re.lua
