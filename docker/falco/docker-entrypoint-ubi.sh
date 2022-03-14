#!/bin/bash
#
# Copyright (C) 2021 The Falco Authors.
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
set -x
rm -fr /usr/src/kernels/ && rm -fr /usr/src/debug/
rm -fr /lib/modules && ln -s $HOST_ROOT/lib/modules /lib/modules
rm -fr /boot && ln -s $HOST_ROOT/boot /boot

exec /docker-entrypoint.sh "$@"
