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
#ifndef _APP_TRADING_DATASTRUCT_H
#define _APP_TRADING_DATASTRUCT_H

#include <app/datastruct.h>

namespace phphs {

enum class direction: uint8_t {
    kLong = 0,
    kShort
};

enum class ordertype: uint8_t {
    kLimit = 0,
    kMarket
};

enum class timecondition: uint8_t {
    kIOC = 0,
    kGFD
};

enum class volumecondition: uint8_t {
    kAny = 0,
    kComplete
};

enum class orderstatus: uint8_t {
    kWaiting = 0,
    kInBook,
    kCancel,
    kError,
    kPartTraded,
    kAllTrade,
    kTimeout
};

enum class hedgeflag: uint8_t {
    kSpeculation = 0,
    kArbitrage,
    kHedge
};

enum class offsetflag: int8_t {
    kOpen = 0,
    kClose,
    kCloseToday,
    kCloseYesterday
};

struct orderfield {
    instrref_t instr_id;
    unsigned int volume;
    unsigned int price;
    enum direction direction;
    enum ordertype ordertype;
    enum timecondition timecondition;
    enum volumecondition volumecondition;
    enum hedgeflag hedgeflag;
    enum offsetflag offsetflag;
};

using orderref_t = uint64_t;

struct orderstat {
    instrref_t instr_id;
    orderstatus status;
    orderref_t orderref;
    unsigned int traded_volume;
    unsigned int volume;
    error_t error;
};

using tradedid_t = uint64_t;

struct tradeinfo {
    instrref_t instr_id;
    tradedid_t traded_id;
    int price;
    unsigned int traded_volume;
};

struct cancelfield {
    orderref_t orderref;
    int errid;
};

} // phphs

#endif // _APP_TRADING_DATASTRUCT_H