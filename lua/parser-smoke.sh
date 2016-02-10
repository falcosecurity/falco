#!/bin/bash

function error_exit_good
{
    echo "Error: '$1' did not parse" 1>&2
    exit 1
}

function error_exit_bad
{
    echo "Error: incorrect filter '$1' parsed ok" 1>&2
    exit 1
}


function good
{
    lua test.lua "$1" || error_exit_good "$1"
}

function bad
{
    lua test.lua "$1" && error_exit_bad "$1"
}

# Filters
good "a"
good "a and b"
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
good "not not a"
good "(not not a)"
good "not a.b=1"
good "not a.a exists"
good "notz"
good "a.b = bla"
good "a.b = 'bla'"
good "a.b = not"
good "a.b contains bla"
good "a.b icontains 'bla'"
good "a.g in ()"
good "a.g in (1, 'a', b)"
good "a.g in ( 1 ,, , b)"

bad "a.g in (1, 'a', b.c)"
bad "a.b = a.a"
bad "(a.b = 1"

# Macros

good "a: a.b exists"
good "a: b and c"
good "a: b"
good "a : b"
good "inbound: (syscall.type=listen and evt.dir='>') or (syscall.type=accept and evt.dir='<')"
bad "a:"

exit 0
