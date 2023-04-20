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
#ifndef _CPLUSPLUS_IRECEIVER_H
#define _CPLUSPLUS_IRECEIVER_H
#include <exception>
#include <type_traits>
#include <concepts> 
#include "cplusplus/tag_invoke.h"
#include "cplusplus/details/ireceiver.h"
namespace cplusplus {

inline constexpr details::set_done_t set_done{};
inline constexpr details::set_error_t set_error{};
inline constexpr details::set_value_t set_value{};

template <typename T, class E = std::exception_ptr>
concept receiver = 
    requires(std::remove_cvref_t<T>&& t, E&& e) {
        std::move_constructible<std::remove_cvref_t<T>> &&
        std::constructible_from<std::remove_cvref_t<T>, T>;
        { set_done(std::move(t)) } noexcept;
        { set_error(std::move(t), std::move(e)) } noexcept;
    };

template <typename T, typename... An>
concept receiver_of = 
    receiver<T> && 
    requires(std::remove_cvref_t<T>&& t, An&&... an)
    {
        set_value(std::move(t), std::move(an)...);
    };

} //cplusplus
#endif //_CPLUSPLUS_IRECEIVER_H