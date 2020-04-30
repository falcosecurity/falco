#!/bin/bash
#
# Copyright (C) 2019 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#


# @kris-nova We have experimental support for ARM and I have tested
# on armv7. Please use this flag as experimental only.
BUILD_ARM=false


cmake ../ \
      -DBUILD_BPF=OFF \
      -DBUILD_WARNINGS_AS_ERRORS="OFF" \
      -DCMAKE_BUILD_TYPE="debug" \
      -DCMAKE_INSTALL_PREFIX="/usr" \
      -DDRAIOS_DEBUG_FLAGS="-D_DEBUG" \
      -DFALCO_ETC_DIR="/etc/falco" \
      -DUSE_BUNDLED_DEPS=OFF

if [ BUILD_ARM ]; then
   driver_config="./driver/src/driver_config.h"
   if ! grep -q "CONFIG_ARM" $driver_config; then
       printf "\n#define CONFIG_ARM\n\n" >> $driver_config
   fi
fi   
