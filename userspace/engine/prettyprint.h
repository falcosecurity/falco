/*
Copyright (C) 2019 The Falco Authors.

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

#include <string>
#include <set>
#include <vector>
#include <list>
#include <map>

#include "sinsp.h"
#include "filter.h"
#include "event.h"

#include "gen_filter.h"


#ifndef FALCO_FALCO_USERSPACE_PRETTYPRINT_H_
#define FALCO_FALCO_USERSPACE_PRETTYPRINT_H_

class prettyprint {
 public:
  static void sinsp_event(sinsp_evt *ev, const char* note = "");

 private:
  static bool has_alerted;
  static void warning();
};

#endif //FALCO_FALCO_USERSPACE_PRETTYPRINT_H_
