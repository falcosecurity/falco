#!/bin/sh

gcc -O2 -fPIC -I$LUA_INCLUDE -c lpcap.c -o lpcap.o
gcc -O2 -fPIC -I$LUA_INCLUDE -c lpcode.c -o lpcode.o
gcc -O2 -fPIC -I$LUA_INCLUDE -c lpprint.c -o lpprint.o
gcc -O2 -fPIC -I$LUA_INCLUDE -c lptree.c -o lptree.o
gcc -O2 -fPIC -I$LUA_INCLUDE -c lpvm.c -o lpvm.o


# For building lpeg.so, which we don't need now that we're statically linking lpeg.a into digwatch
#gcc -shared -o lpeg.so -L/usr/local/lib lpcap.o lpcode.o lpprint.o lptree.o lpvm.o
#gcc -shared -o lpeg.so -L/usr/local/lib lpcap.o lpcode.o lpprint.o lptree.o lpvm.o

/usr/bin/ar cr lpeg.a lpcap.o lpcode.o lpprint.o lptree.o lpvm.o
/usr/bin/ranlib lpeg.a

chmod ug+w re.lua
