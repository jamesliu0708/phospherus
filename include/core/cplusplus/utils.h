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
#ifndef _CPLUSPLUS_UTILS_H
#define _CPLUSPLUS_UTILS_H

namespace cplusplus {
template <typename F, typename...Vs>
constexpr bool f_invocable = std::is_invocable_v<F, Vs...>;

template <typename F, typename...Vs>
constexpr bool f_return_value = f_invocable<F, Vs...> &&
    (!std::is_void_v<std::invoke_result_t<F, Vs...>>);

template <typename F, typename...Vs>
constexpr bool f_return_void = f_invocable<F, Vs...> &&
    (std::is_void_v<std::invoke_result_t<F, Vs...>>);

template <typename F, typename...Vs>
constexpr bool f_nothrow_invocable = std::is_nothrow_invocable_v<F, Vs...>;

template <typename F, typename...Vs>
constexpr bool f_throw_invocable = std::is_invocable_v<F, Vs...> &&
    (!f_nothrow_invocable<F, Vs...>);
    
} // cplusplus
#endif // _CPLUSPLUS_UTILS_H