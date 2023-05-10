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

// Date: Tue May 24 18:57:02 CST 2023
#ifndef _RT_SEARCH_H
#define _RT_SEARCH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Performs a lower-bounds search for values from target in src.
 * creates a list of indices such that the distance between the indicies
 * is equal in bytes to the size of a cachline, then uses this list to
 * search for targets
 * 
 * @param src The data array; array to search for lower bounds within
 * @param n Number of elements in src
 * @param target The targets  elements to find lower bounds for in src
 * @return int lower bound indices
 */
int skip_list_search(uint64_t* __restrict__ src, int n, uint64_t target);

/**
 * Performs a lower-bounds search for values from target in src.
 * incrementally adjusts the bounds of each search so that correlations
 * between targets are utilized 
 * 
 * @param src The data array; array to search for lower bounds within
 * @param n Number of elements in src
 * @param target The targets  elements to find lower bounds for in src
 * @return int lower bound indices
 */
int hunt_locate_search(uint64_t* __restrict__ src, int n, uint64_t target);

/**
 * Performs a lower-bounds search for values from target in src.
 * 
 * @param src The data array; array to search for lower bounds within
 * @param n Number of elements in src
 * @param target The targets  elements to find lower bounds for in src
 * @return int lower bound indices
 */
int linear_search(uint64_t* __restrict__ src, int n, uint64_t target);

/**
 * Performs a lower-bounds search for values from target in src.
 * 
 * @param src The data array; array to search for lower bounds within
 * @param n Number of elements in src
 * @param target The targets  elements to find lower bounds for in src
 * @return int lower bound indices
 */
int binary_search(uint64_t* __restrict__ src, int n, uint64_t target);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // _RT_SEARCH_H