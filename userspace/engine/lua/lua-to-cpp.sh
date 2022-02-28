#!/bin/bash

set -euo pipefail

LUA_FILE_DIR=$1
LYAML_LUA_DIR=$2
OUTPUT_DIR=$3

MODULE_SYMS=()
CODE_SYMS=()

function add_lua_file {
    filename=$1
    is_module=$2

    # Take the basename of the file
    BASE_NAME=$(basename ${file} .lua)
    SYMBOL_NAME="${BASE_NAME}_lua_file_contents"
    FILE_CONTENTS=$(<${file})

    # Add a symbol to the .cc file containing the contents of the file
    echo "const char *${SYMBOL_NAME}=R\"LUAFILE(${FILE_CONTENTS})LUAFILE\";" >> ${OUTPUT_DIR}/falco_engine_lua_files.cpp

    # Add an extern reference to the .hh file
    echo "extern const char *${SYMBOL_NAME};" >> ${OUTPUT_DIR}/falco_engine_lua_files.hh

    if [[ "${is_module}" == "true" ]]; then
	# Determine the module name for the file
	if [[ "${file}" == *"/"* ]]; then
	    MODULE_NAME=$(echo ${file} | tr / . | sed -e 's/.lua//')
	else
	    MODULE_NAME=$(basename ${file} .lua)
	fi

	# Add the pair (string contents, module name) to MODULE_SYMS
	PAIR=$(echo "{${SYMBOL_NAME},\"${MODULE_NAME}\"}")
	MODULE_SYMS+=(${PAIR})
    else
	# Add the string to CODE_SYMS
	CODE_SYMS+=(${SYMBOL_NAME})
    fi
}

cat <<EOF > ${OUTPUT_DIR}/falco_engine_lua_files.cpp
// Automatically generated. Do not edit
#include "falco_engine_lua_files.hh"
EOF

cat <<EOF > ${OUTPUT_DIR}/falco_engine_lua_files.hh
#pragma once
// Automatically generated. Do not edit
#include <list>
#include <utility>
EOF

# lyaml and any files in the "modules" subdirectory are treated as lua
# modules.
pushd ${LYAML_LUA_DIR}
for file in *.lua */*.lua; do
    add_lua_file $file "true"
done
popd

# Any .lua files in this directory are treated as code with functions
# to execute.
pushd ${LUA_FILE_DIR}
for file in ${LUA_FILE_DIR}/*.lua; do
    add_lua_file $file "false"
done
popd

# Create a list of lua module (string, module name) pairs from MODULE_SYMS
echo "extern std::list<std::pair<const char *,const char *>> lua_module_strings;" >> ${OUTPUT_DIR}/falco_engine_lua_files.hh
echo "std::list<std::pair<const char *,const char *>> lua_module_strings = {$(IFS=, ; echo "${MODULE_SYMS[*]}")};" >> ${OUTPUT_DIR}/falco_engine_lua_files.cpp

# Create a list of lua code strings from CODE_SYMS
echo "extern std::list<const char *> lua_code_strings;" >> ${OUTPUT_DIR}/falco_engine_lua_files.hh
echo "std::list<const char *> lua_code_strings = {$(IFS=, ; echo "${CODE_SYMS[*]}")};" >> ${OUTPUT_DIR}/falco_engine_lua_files.cpp
