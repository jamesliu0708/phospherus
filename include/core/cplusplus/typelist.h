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

// Date: Wed Apr 26 19:42:15 CST 2023
#ifndef _CPLUSCPLUS_TYPELIST_H
#define _CPLUSCPLUS_TYPELIST_H

namespace cplusplus {
template<typename ...Ts>
struct type_list {
    /// <summary>
    /// type_list<t1, t2, ...>::apply<F> is equivalant to F<t1, t2, ...>.
    /// F must be a template that accepts multiple types
    /// </summary>
    template<template <typename...> class F>
    using apply = F<Ts...>;
};

template<typename ...Ts>
struct type_count {
    static constexpr int value = sizeof...(Ts);
};

} // cplusplus

#include "cplusplus/details/typelist.h"

template<typename ...TypeList>
using concated_type_list = typename details::concat_type_lists_impl<TypeList...>::type;

template<typename ...TypeList>
using concated_type_set = typename details::concat_type_sets_impl<TypeList...>::type;

/// <summary>
/// For a type_list of type_list, 
/// i.e., for T = type_list< type_list<Us ...>, type_list<Vs...>, ...>
/// zip_apply<T, Outer, Inner> is equivalent to
/// Outer<Inner<Us...>, Inner<Vs...>, ...>
/// </summary>
template <
    typename ListOfLists,
    template <typename...> class Outer,
    template <typename...> class Inner
>
using zip_apply = typename ListOfLists::template apply<
    details::zip_apply_impl<Outer, Inner>::template apply
>;

#endif // _CPLUSCPLUS_TYPELIST_H