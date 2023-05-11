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

#include <type_traits>

namespace cplusplus {
namespace details {
/// <summary>
/// Used to concat multiple type_lists into a single type_list.
/// concat_type_lists<type_list1<t11, t12...>, type_list2<t21, t22...>, ...>::type_list
///  should return type_list<t11, t12, ..., t21, t22, ..., ...>
/// </summary>
/// <typeparam name="...TypeLists">A list of type_lists to be cancatenated.</typeparam>
template<typename ...TypeLists>
struct concat_type_lists_impl;

template<>
struct concat_type_lists_impl<> {
    using type = type_list<>;
};

template<typename... Ts>
struct concat_type_lists_impl<type_list<Ts...>> {
    using type = type_list<Ts...>;
};

template<typename ...Ts, typename ...Us>
struct concat_type_lists_impl<type_list<Ts...>, type_list<Us...>> {
    using type = type_list<Ts..., Us...>;
};

template <typename... Ts, typename... Us, typename... Vs, typename... OtherLists>
struct concat_type_lists_impl<type_list<Ts...>, type_list<Us...>, type_list<Vs...>, OtherLists...>
    : concat_type_lists_impl<type_list<Ts..., Us..., Vs...>, OtherLists...> {};

/// <summary>
/// Used to concat multiple type_lists into a single type_list.
/// It acts as a set and only one of the same types will be in the result list.
/// </summary>
/// <typeparam name="...TypeSets">
/// A list of type_list, it's assumed that each type_list is already a set.
/// </typeparam>
template<typename ...TypeSets>
struct concat_type_sets_impl;

template<>
struct concat_type_sets_impl<> {
    using type = type_list<>;
};

template<typename...Ts>
struct concat_type_sets_impl<type_list<Ts...>> {
    using type = type_list<Ts...>;
};

template <typename T, typename... Ts>
inline constexpr bool is_one_of_v = (std::is_same_v<T, Ts> || ...);

template <typename T, typename... Ts>
concept one_of = (std::is_same_v<T, Ts> || ...);

template <typename... Ts, typename... Us, typename... OtherLists>
struct concat_type_sets_impl<type_list<Ts...>, type_list<Us...>, OtherLists...>
    : concat_type_sets_impl<
        typename concat_type_lists_impl<
            type_list<Ts...>,
            std::conditional_t<
                is_one_of_v<Us, Ts...>,
                type_list<>,
                type_list<Us>
            >...
        >::type,
        OtherLists...> 
{};

template <template <typename...> class Outer, template <typename...> class Inner>
struct zip_apply_impl {
    template <typename... TypeLists>
    using apply = Outer<typename TypeLists::template apply<Inner>...>;
};

} //details

} // cpluspluc