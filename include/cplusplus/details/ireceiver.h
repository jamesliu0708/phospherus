// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Date: Wed Apr 15 18:47:15 CST 2023
#ifndef _CPLUSPLUS_DETAILS_IRECEIVER_H
#define _CPLUSPLUS_DETAILS_IRECEIVER_H
#include "cplusplus/tag_invoke.h"

namespace cplusplus {
namespace details {
struct set_done_t {
    template <typename R>
        requires nothrow_tag_invocable<set_done_t, R>
    auto operator()(R&& r) const noexcept 
    {
        return tag_invoke(set_done_t{}, std::move(r));
    }
};

struct set_error_t {
    template<typename R, typename E>
        requires nothrow_tag_invocable<set_error_t, R, E>
    auto operator()(R&& r, E&& e) const noexcept
    {
        return tag_invoke(set_error_t{}, std::move(r), std::move(e));
    }
};

struct set_value_t {
    template<typename R, typename... Vs>
        requires tag_invocable<set_value_t, R, Vs...>
    auto operator()(R&& r, Vs &&... vs) const
        noexcept(nothrow_tag_invocable<set_value_t, R, Vs...>)
    {
        return tag_invoke(set_value_t{}, std::move(r), std::move(vs)...);
    }
};
} // details
} // cplusplus

#endif // _CPLUSPLUS_DETAILS_IRECEIVER_H