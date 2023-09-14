// SPDX-License-Identifier: Apache-2.0
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

#pragma once

#include <string>

namespace falco {
namespace app {

struct run_result
{
    // Successful result
    inline static run_result ok()
    {
        run_result r;
        r.success = true;
        r.errstr = "";
        r.proceed = true;
        return r;
    }

    // Successful result that causes the program to stop
    inline static run_result exit()
    {
        run_result r = ok();
        r.proceed = false;
        return r;
    }

    // Failure result that causes the program to stop with an error
    inline static run_result fatal(const std::string& err)
    {
        run_result r;
        r.success = false;
        r.errstr = err;
        r.proceed = false;
        return r;
    }

    // Merges two run results into one
    inline static run_result merge(const run_result& a, const run_result& b)
    {
        auto res = ok();
        res.proceed = a.proceed && b.proceed;
        res.success = a.success && b.success;
        res.errstr = a.errstr;
        if (!b.errstr.empty())
        {
            res.errstr += res.errstr.empty() ? "" : "\n";
            res.errstr += b.errstr;
        }
        return res;
    }

    run_result(): success(true), errstr(""), proceed(true) {}
    virtual ~run_result() = default;
    run_result(run_result&&) = default;
    run_result& operator = (run_result&&) = default;
    run_result(const run_result&) = default;
    run_result& operator = (const run_result&) = default;


    // If true, the method completed successfully.
    bool success;
    // If success==false, details on the error.
    std::string errstr;
    // If true, subsequent methods should be performed. If
    // false, subsequent methods should *not* be performed
    // and falco should tear down/exit/restart.
    bool proceed;
};

}; // namespace app
}; // namespace falco
