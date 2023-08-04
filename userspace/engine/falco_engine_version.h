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
//   FALCO="falco -c ./falco.yaml"
//   echo $($FALCO --version | grep 'Engine:' | awk '{print $2}') $(echo $($FALCO --version | grep 'Schema version:' | awk '{print $3}') $($FALCO --list --markdown | grep '^`' | sort) $($FALCO --list-syscall-events | sort) | sha256sum)
// It represents the fields supported by this version of Falco,
// the event types, and the underlying driverevent schema. It's used to
// detetect changes in engine version in our CI jobs.
#define FALCO_ENGINE_CHECKSUM "96d8d3fc828e5c8c16184d66d0e7d5970864249e9b20cd736acaf70dc6431e0f"
