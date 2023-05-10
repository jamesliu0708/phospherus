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
#include <rtstd/search.h>

//  We tried many different combinations of
// flags for both GCC and Intel. The flags that worked best
// for performance
#pragma GCC push_options
#pragma GCC optimize("-fstrict-aliasing -ftree-vectorize \
    -march=native -mtune=native \
    -fopt-info-vec-all=gcc optrprt -fopenmp-simd \
    -O3")
/**
 * @brief Branchless choice of two integers
 * 
 * @param condition 1 for True, 0 for False
 * @param val_true Return if condition == 1
 * @param val_false Return if condition == 0
 * @return int Either valTrue or valFalse
 */
static inline int choose(int condition, int val_true, int val_false) {
    return (condition * val_true) | (!condition * val_false);
}

static inline int min(int a, int b) {
    const int cond = a < b;
    return (cond * a) | (!cond * b);
}

static inline int max(int a, int b) {
    const int cond = a > b;
    return (cond * a) | (!cond * b);
}

static inline inline_binary_search(int start, int end, uint64_t *__restrict__ x, uint64_t target) {
    while ((end - start) > 1) {
        const int midPoint = (end + start) / 2;
        const int c = target < x[midPoint];
        end = choose(c, midPoint, end);
        start = choose(!c, midPoint, start);
    }
    return choose(target < x[end], start, end);
}

int linear_search(uint64_t* __restrict__ src, int n, uint64_t target)
{
    int i = 1;
    for (; i < n; i++) {
        if (src[i] > target) break;
    }
    return i - 1;
}

int binary_search(uint64_t* __restrict__ src, int n, uint64_t target)
{
    return inline_binary_search(0, n - 1, src, target);
}

int hunt_locate_search(uint64_t* __restrict__ src, int n, uint64_t target)
{
    const uint64_t min_val = src[0];
    const uint64_t max_val = src[n - 1];
    int lowbound;
    int start = 0, end = n - 1;

    if (target < min_val) {
        lowbound = 0;
        return lowbound;
    } else if (target > max_val) {
        lowbound = n - 1;
        return lowbound;
    } else {
        int j = 1;
        while (start >= 0 && end < n) {
            if (target > src[end]) {
                start += end;
                end += j;
            } else if (target < src[start]) {
                end = start;
                start -= j;
            } else {
                break;
            }
            j <<= 1;
        }
         // Binary search within bounds
        end = min(end, n - 1);
        start = inline_binary_search(max(start, 0), end, src, target);
        lowbound = start;
    }

    return lowbound;
}

int skip_list_search(uint64_t *__restrict__ src, int n, uint64_t target)
{
    const uint64_t min_val = src[0];
    const uint64_t max_val = src[n - 1];
    int lowbound;

    if (target < min_val) {
        lowbound = 0;
    } else if (target > max_val) {
        lowbound = n - 1;
    } else {
        
    }
}

#pragma GCC pop_options