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
#define FALCO_ENGINE_VERSION (23)

// This is the result of running the following command:
//   FALCO="falco -c ./falco.yaml"
//   echo $($FALCO --version | grep 'Engine:' | awk '{print $2}') $(echo $($FALCO --version | grep 'Schema version:' | awk '{print $3}') $($FALCO --list --markdown | grep '^`' | sort) $($FALCO --list-syscall-events | sort) | sha256sum)
// It represents the fields supported by this version of Falco,
// the event types, and the underlying driverevent schema. It's used to
// detetect changes in engine version in our CI jobs.
#define FALCO_ENGINE_CHECKSUM "fc01e84426728f6adc67fd7e7eca3d33b0dfc21c7dde14435cc88376dbaf04c5"
