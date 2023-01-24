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

#include <unordered_set>
#include <string>

std::string concat_syscalls_names(std::unordered_set<std::string> const syscalls_names);
// TODO interim helper methods below shall be integrated into sinsp APIs
std::unordered_set<uint32_t> get_syscalls_ppm_codes(const std::unordered_set<std::string> syscalls_names);
std::unordered_set<std::string> get_difference_syscalls_names(std::unordered_set<std::string> syscalls_names_reference, std::unordered_set<std::string> syscalls_names_comparison);
