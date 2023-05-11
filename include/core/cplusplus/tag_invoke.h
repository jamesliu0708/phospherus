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
#ifndef _CPLUSPLUS_TAG_INVOKE_H
#define _CPLUSPLUS_TAG_INVOKE_H
#include <type_traits>
#include "details/tag_invoke.h"
namespace cplusplus {

inline constexpr details::tag_invoke_t tag_invoke{};

template<auto& Tag> 
using tag_t = std::decay_t<decltype(Tag)>;

template<typename Tag, typename... Args> 
concept tag_invocable = 
    std::is_invocable_v<decltype(tag_invoke), Tag, Args...>;

template<typename Tag, typename... Args> 
concept nothrow_tag_invocable = 
    std::is_nothrow_invocable_v<decltype(tag_invoke), Tag, Args...>; 

template<typename Tag, typename... Args> 
using tag_invoke_result_t = std::invoke_result_t<decltype(tag_invoke), Tag, Args...>; 

} // cplusplus

#endif // _CPLUSPLUS_TAG_INVOKE_H
