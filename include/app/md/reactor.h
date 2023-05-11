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

// Date: Mon May 8 16:50:15 CST 2023
#ifndef _APP_MD_DRIVER_H
#define _APP_MD_DRIVER_H

#include <stdbool.h>

/**
 * Marketdata reactor initialization function.
 * 
 * The function invoked when the user creates the reactor
 * 
 * @param private_data
 *  private data may be used in initialization
 */
typedef bool (*md_reactor_init_t) (void* private_data);
/**
 * Marketdata filter function
 * 
 * The function invoked when market data received using rx_burst
 * 
 * @param data
 *  The pointer to pointer to market data packets
 * @param cnt
 *  The count of package count
 * @param out
 *  The packet pass the filter
 * @return
 *  The number of messages that passed the filter
 */
typedef int (*md_reactor_filter_t) (void** data, unsigned int cnt, void** out);
/**
 * Marketdata process function
 * 
 * The function invoked after filter was invoked
 * 
 * @param data
 *  The pointer to pointer to market data packets
 * @param cnt
 *  the count of package count
 */
typedef void (*md_reactor_process_t) (void** data, unsigned int cnt, struct mdfield** out);
/**
 * Marketdata reactor finalize function
 * 
 * The function invoked when reactor need release
 * 
 * @param private_data
 *  private data may be used in initialization
 */
typedef bool (*md_reactor_fini_t) (void* private_data);

struct md_reactor_ops {
    md_reactor_init_t ini; /**< reactor init function */
    md_reactor_filter_t filter; /**< market data filter function */
    md_reactor_process_t process; /**< market data process function */
    md_reactor_fini_t fini; /**< reactor fini function */
};

#define MARKET_DATA_REACTOR_NAMESIZE 32 /**< Max length of ops struct name */
struct md_reactor {
    char name[MARKET_DATA_REACTOR_NAMESIZE]; /**< Name of md reactor */
    struct md_reactor_ops * ops;
}

#endif // _APP_MD_DRIVER_H