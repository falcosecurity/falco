/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// The version of this Falco engine.
#define FALCO_ENGINE_VERSION (19)

// This is the result of running "falco --list -N | sha256sum" and
// represents the fields supported by this version of Falco. It's used
// at build time to detect a changed set of fields.

// This is the result of running the following command:
//   echo $(falco -c ./falco.yaml --version | grep 'Engine:' | awk '{print $2}') $(echo $(falco -c ./falco.yaml --version | grep 'Schema version:' | awk '{print $3}') $(falco -c ./falco.yaml --list --markdown | grep '^`' | sort) $(falco -c ./falco.yaml --list-syscall-events | sort) | sha256sum)
// It represents the fields supported by this version of Falco,
// the event types, and the underlying driverevent schema. It's used to
// detetect changes in engine version in our CI jobs.
#define FALCO_ENGINE_CHECKSUM "1d7f91f22d40074c56c705f5e494b7fae51aee1b7ababc8c70cfa63c6d6671c2"
