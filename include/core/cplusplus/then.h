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
#ifndef _CPLUSPLUS_THEN_H
#define _CPLUSPLUS_THEN_H
#include "cplusplus/typelist.h"
#include "cplusplus/details/then.h"
namespace cplusplus {
template <typename S, typename F>
using then_sender = details::then_sender_t<S, F>;
inline constexpr details::then_t then{};

namespace details {
template <typename F>
struct then_closure_t {
    F f_;
    template <typename Self, sender S>
        requires std::is_same_v<std::remove_cvref_t<Self>, then_closure_t>
    inline friend auto operator | (S&& s, Self&& t) 
    {
        return then(std::forward<S>(s), std::move(t.f_));
    }
};
} // details

template <typename F>
auto details::then_t::operator()(F&& f) const noexcept {
    return details::then_closure_t<std::remove_cvref_t<F>>{ std::forward<F>(f)  };
}
} // cplusplus
#endif // _CPLUSPLUS_THEN_H