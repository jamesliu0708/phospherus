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
#ifndef _CORE_GENERIC_H
#define _CORE_GENERIC_H
#include <stdint.h>

typedef uint8_t  lcoreid_t;

#define RTE_CACHE_LINE_SIZE_ROUNDUP(size) \
	(RTE_CACHE_LINE_SIZE * ((size + RTE_CACHE_LINE_SIZE - 1) / RTE_CACHE_LINE_SIZE))

#define NUMA_ENABLE 1

#define NUMA_NO_CONFIG 0xFF
#define UMA_NO_CONFIG  0xFF

#ifndef NUMA_SUPPORT
#define NUMA_SUPPORT NUMA_ENABLE
#endif // NUMA_SUPPORT

#endif // _CORE_GENERIC_H