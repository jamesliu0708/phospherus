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

// Date: Mon May 8 13:03:15 CST 2023
#ifndef _APP_MD_DATASTRUCT_H
#define _APP_MD_DATASTRUCT_H

#include <app/datastruct.h>
#include <x86intrin.h>

union instrument {
#ifdef __AVX256__
    __m256i _;
#endif // __AVX256__
    char id[32];
};

struct mdfield {
    instrref_t instr_id;
    int bid_price[5];
    int bid_volume[5];
    int ask_price[5];
    int ask_volume[5];
};

#endif // _APP_MD_DATASTRUCT_H