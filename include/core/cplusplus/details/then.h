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
#ifndef _CPLUSPLUS_DETAILS_THEN_H
#define _CPLUSPLUS_DETAILS_THEN_H
#include <type_traits>
#include <functional>
#include "cplusplus/isender.h"
#include "cplusplus/ireceiver.h"

namespace cplusplus {
namespace details {

template <typename Result, typename=void>
struct result_overload {
    using type = type_list<Result>;
};

template <typename Result>
struct result_overload<Result, std::enable_if_t<std::is_void_v<Result>>> {
    using type = type_list<>;
};

template <receiver R, typename F>
struct then_receiver_impl {
    [[no_unique_address]] R out_r_;
    [[no_unique_address]] F f_;
    template <typename...Vs>
        requires f_nothrow_invocable<F, Vs...> && f_return_void<F, Vs...>
            && receiver_of<R>
    friend auto tag_invoke(tag_t<set_value>, then_receiver_impl&& r, Vs&&...vs) noexcept 
    {
        std::invoke(std::move(r.f_), std::forward<Vs>(vs)...);
        set_value(std::move(r.out_r_));
    }

    template <typename...Vs>
        requires f_nothrow_invocable<F, Vs...> && f_return_value<F, Vs...>
            && receiver_of<R, std::invoke_result_t<F, Vs...>>
    friend auto tag_invoke(tag_t<set_value>, then_receiver_impl&& r, Vs&&...vs) noexcept
    {
        set_value(std::move(r.out_r_), std::invoke(std::move(r.f_), std::forward<Vs>(vs)...));
    }

    template <typename...Vs>
        requires f_throw_invocable<F, Vs...> && f_return_void<F, Vs...>
            && receiver_of<R>
    friend auto tag_invoke(tag_t<set_value>, then_receiver_impl&& r, Vs&&...vs) noexcept
    {
        try {
            std::invoke(std::move(r.f_), std::forward<Vs>(vs)...);
            set_value(std::move(r.out_r_));
        } catch (...) {
            set_error(std::move(r.out_r_), std::current_exception());
        }
    }

    template <typename...Vs>
        requires f_throw_invocable<F, Vs...> && f_return_value<F, Vs...>
            && receiver_of<R, std::invoke_result_t<F, Vs...>>
    friend auto tag_invoke(tag_t<set_value>, then_receiver_impl&& r, Vs&&...vs) noexcept
    {
        try {
            set_value(std::move(r.out_r_), std::invoke(std::move(r.f_), std::forward<Vs>(vs)...));
        } catch (...) {
            set_error(std::move(r.out_r_), std::current_exception());
        }
    }

    template <typename E>
    friend auto tag_invoke(tag_t<set_error>, then_receiver_impl&& r, E&& e) noexcept
    {
        set_error(std::move(r.out_r_), std::move(e));
    }

    friend auto tag_invoke(tag_t<set_done>, then_receiver_impl&& r) noexcept
    {
        set_done(std::move(r.out_r_));
    }
};

template <typename R, typename F>
using then_reciever_t = then_receiver_impl<std::remove_cvref_t<R>, std::decay_t<F>>;

template <typename S, typename F>
struct then_sender_impl {
    S pred_;
    F f_;
    template <typename...Args>
    using result = type_list<
        typename result_overload<std::invoke_result_t<F, Args...>>::type
    >;
    template<
        template <typename...>class Tuple, 
        template <typename...>class Variant
    >
    using value_type = zip_apply<
        typename sender_traits<S>::template value_type<result, concated_type_set>,
        Variant,
        Tuple
    >;

    template <template <typename...>class Variant>
    using error_type = concated_type_set<
        typename sender_traits<S>::template error_type<type_list>,
        type_list<std::exception_ptr>
    >::template apply<Variant>;

    static constexpr bool sends_done = sender_traits<S>::sends_done;

    template <typename R>
    using receiver_t = then_reciever_t<R, F>;

    template <typename Self, typename R>
        requires std::is_same_v<std::remove_cvref_t<Self>, then_sender_impl>
            && sender_to<S, receiver_t<std::remove_cvref_t<R>>>
    friend auto tag_invoke(tag_t<connect>, Self&& s, R&& r)
        noexcept(
            std::is_nothrow_constructible_v<std::remove_cvref_t<R>, R> &&
            std::is_nothrow_constructible_v<F, F> &&
            nothrow_tag_invocable<connect_t, S, receiver_t<std::remove_cvref_t<R>>>
        )
    {
        return 
            connect(
                std::forward<Self>(s).pred_,
                receiver_t<std::remove_cvref_t<R>>{
                    std::move(r),
                    std::move(std::forward<Self>(s).f_)
                }
            );
    }
};

template <typename S, typename F>
using then_sender_t = then_sender_impl<S, F>;

struct then_t 
{
    template <typename F>
    auto operator()(F && f) const noexcept;

    template <typename S, typename F>
        requires tag_invocable<then_t, S, F>
    auto operator()(S&& s, F&& f) const 
        noexcept(f_nothrow_invocable<then_t, S, F>)
    {
        return tag_invoke(then_t{}, std::move(s), std::move(f));
    }
    template <typename S, typename F>
        requires (!tag_invocable<then_t, S, F>)
    auto operator()(S&& s, F&& f) const
        noexcept(std::is_nothrow_constructible_v<
            then_sender_t<std::remove_cvref_t<S>, std::remove_cvref_t<F>>, 
            S,
            F
        >) 
    {
        return then_sender_t<std::remove_cvref_t<S>, std::remove_cvref_t<F>>(
            std::move(s),
            std::move(f)
        );
    }
};
} // details
} // cplusplus

#endif // _CPLUSPLUS_DETAILS_THEN_H