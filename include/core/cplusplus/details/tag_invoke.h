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
#ifndef _TAG_INVOKE_DETAILS_H
#define _TAG_INVOKE_DETAILS_H
namespace cplusplus {
namespace details {
   void tag_invoke();
   struct tag_invoke_t 
   {
      template<typename Tag, typename... Args>
      constexpr auto operator() (Tag tag, Args &&... args) const
         noexcept(noexcept(tag_invoke(static_cast<Tag &&>(tag), static_cast<Args &&>(args)...)))
         -> decltype(tag_invoke(static_cast<Tag &&>(tag), static_cast<Args &&>(args)...))
      {
         return tag_invoke(static_cast<Tag &&>(tag), static_cast<Args &&>(args)...);
      }
   };
} // details
} // cplusplus
#endif // _TAG_INVOKE_DETAILS_H