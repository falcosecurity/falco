/*
Copyright (C) 2016-2018 Draios Inc dba Sysdig.

This file is part of falco.

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

// The version of rules/filter fields/etc supported by this falco
// engine.
#define FALCO_ENGINE_VERSION (3)

// This is the result of running "falco --list -N | sha256sum" and
// represents the fields supported by this version of falco. It's used
// at build time to detect a changed set of fields.
#define FALCO_FIELDS_CHECKSUM "b1bf297373fd08c91ffc978dbff5b349ec9338e25b54f70f23e40a609d47924b"
