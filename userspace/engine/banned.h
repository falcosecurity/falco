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

#pragma once

// BAN macro defines `function` as an invalid token that says using
// the function is banned. This throws a compile time error when the
// function is used.
#define BAN(function) using_##function##_is_banned

// BAN_ALTERNATIVE is same as BAN but the message also provides an alternative
// function that the user could use instead of the banned function.
#define BAN_ALTERNATIVE(function, alternative) using_##function##_is_banned__use_##alternative##_instead

#undef strcpy
#define strcpy(a, b) BAN(strcpy)

#undef vsprintf
#define vsprintf(a, b, c) BAN_ALTERNATIVE(vsprintf, vsnprintf)

#undef sprintf
#define sprintf(a, b, ...) BAN_ALTERNATIVE(sprintf, snprintf)

#undef strcat
#define strcat(a, b) BAN(strcat)

#undef strncat
#define strncat(a, b, c) BAN(strncat)

#undef strncpy
#define strncpy(a, b, c) BAN(strncpy)

#undef swprintf
#define swprintf(a, b, c, ...) BAN_ALTERNATIVE(swprintf, snprintf)

#undef vswprintf
#define vswprintf(a, b, c, d) BAN_ALTERNATIVE(vswprintf, vsnprintf)
