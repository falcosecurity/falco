/*

Copyright (c) 2021 The Falco Authors

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef __BUILTINS_H
#define __BUILTINS_H

/*
 * Make sure to always use the inline LLVM built-ins.
 * This is done to avoid using any different implementation at all costs
 * since we always want to use the specific LLVM builtins in this context
 * and nothing else.
 */

#ifdef memset
#undef memset
#endif
#define memset __builtin_memset

#ifdef memcpy
#undef memcpy
#endif
#define memcpy __builtin_memcpy

#endif // __BUILTINS_H