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
#ifndef _CPLUSPLUS_ISENDER_H
#define _CPLUSPLUS_ISENDER_H
#include <concepts>
#include <type_traits>
#include "cplusplus/tag_invoke.h"
#include "cplusplus/ireceiver.h"
#include "cplusplus/details/isender.h"
#include "cplusplus/utils.h"
namespace cplusplus {

inline constexpr details::connect_t connect{};
inline constexpr details::start_t start{};

template <typename S>
struct sender_traits {
    using __unspecialized = void;
};

template <typename S> requires(details::has_sender_types<S>)
struct sender_traits<S>
{
    template <
        template <typename...> class Tuple,
        template <typename...> class Variant
        >
    using value_type = S::template value_type<Tuple, Variant>;
    template <template <typename...> class Variant>
    using error_type = S::template error_type<Variant>;
    static constexpr bool sends_done = S::sends_done;
};

template <typename S>
concept sender = 
    std::move_constructible<std::remove_cvref_t<S>>
     && !requires 
    {
        typename sender_traits<std::remove_cvref_t<S>>::__unspecialized;
    };

template <typename S, typename R>
concept sender_to = sender<S> && receiver<R> &&
    requires (std::remove_cvref_t<S>&& s, std::remove_cvref_t<R>&& r)
    {
        connect(std::move(s), std::move(r));
    };

} // cplusplus
