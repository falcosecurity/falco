#!/bin/bash

set -ex

PREFIX=$1

if [ -z $PREFIX ]; then
    PREFIX=.
fi

mkdir -p $PREFIX

gcc -O2 -fPIC -I$LUA_INCLUDE -c lpcap.c -o $PREFIX/lpcap.o
gcc -O2 -fPIC -I$LUA_INCLUDE -c lpcode.c -o $PREFIX/lpcode.o
gcc -O2 -fPIC -I$LUA_INCLUDE -c lpprint.c -o $PREFIX/lpprint.o
gcc -O2 -fPIC -I$LUA_INCLUDE -c lptree.c -o $PREFIX/lptree.o
gcc -O2 -fPIC -I$LUA_INCLUDE -c lpvm.c -o $PREFIX/lpvm.o


# For building lpeg.so, which we don't need now that we're statically linking lpeg.a into falco
#gcc -shared -o lpeg.so -L/usr/local/lib lpcap.o lpcode.o lpprint.o lptree.o lpvm.o
#gcc -shared -o lpeg.so -L/usr/local/lib lpcap.o lpcode.o lpprint.o lptree.o lpvm.o

pushd $PREFIX
/usr/bin/ar cr lpeg.a lpcap.o lpcode.o lpprint.o lptree.o lpvm.o
/usr/bin/ranlib lpeg.a
popd

chmod ug+w re.lua
