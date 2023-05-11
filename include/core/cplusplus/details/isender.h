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
#ifndef _CPLUSPLUS_DETAILS_ISENDER_H
#define _CPLUSPLUS_DETAILS_ISENDER_H
#include <type_traits>
#include "cplusplus/tag_invoke.h"
namespace cplusplus {
namespace details {
struct connect_t {
    template <typename S, typename R>
        requires tag_invocable<connect_t, S, R>
    auto operator()(S&& s, R&& r) const 
        noexcept(nothrow_tag_invocable<connect_t, S, R>)
    {
        return tag_invoke(connect_t{}, std::move(s), std::move(r));
    }
};

struct start_t {
    template <typename OP>
        requires tag_invocable<start_t, OP>
    auto operator()(OP&& op) const noexcept
    {
        return tag_invoke(start_t{}, std::forward<OP>(op));
    }
};

template <template <template <typename...> class, template <typename...> class> class>
struct has_value_types{};

template <template <template <typename...> class> class>
struct has_error_types{};

template <typename S>
concept has_sender_types = 
    requires() {
        std::integral_constant<bool, S::sends_done>{},
        has_value_types<S::template value_type>{},
        has_error_types<S::template error_type>{};
    };

} // details
} // cplusplus

#endif // _CPLUSPLUS_DETAILS_ISENDER_H