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

// Date: Thur Apr 15 14:13:15 CST 2023
#ifndef _RT_ETH_H
#define _RT_ETH_H

#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mempool.h>
#include <rte_mbuf_dyn.h>
#include <rte_common.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct rte_port;
struct pss_port;
/**
 * Initialize global configuration
 * 
 * @param gpath 
 *  global configuration path
 * @return int 
 *  - On success, zero.
 * 	- On failure, a negative value.
 */
int rte_gcfg_setup(const char* gpath);

void rte_rst_config(uint16_t pid);

/**
 *  Initialize the log module of the ethdev layer
 * 	
 * 	Register a dynamic log type and set the level for log module
 * 	If a log is already registered with the same type, the log 
 *  level will be override the previous one
 *  
 * @param logname 
 * 	The string identifying the log type.
 * @return int 
 * 	- >0: success, the returned value is the log type identifier.
 * 	- (-ENOMEM): cannot allocate memory.
 *  - -1: level is invalid.
 */
int rt_eth_log_setup(const char* logname, uint32_t level);

/**
 * Setup dev port
 *  Load the configuration from a file and initialize dev port
 * @param port
 *  A pointer to port should be initialized.
 * @return int 
 *  - On success, zero.
 * 	- On failure, a negative value.
 */
int rte_eth_setup(struct pss_port* port);

/**
 * @brief 
 * 
 * @param port 
 * @return int 
 */
int rte_eth_cleanup(struct rte_port* port);

/**
 * Start the port
 *  
 * @param pid 
 * @return int 
 */
int rte_port_start(uint16_t pid, struct rte_port* port);

/**
 *  Stop the port
 * 
 * @param pid 
 * 	port id which will be stopped
 */
int rte_port_stop(uint16_t pid, struct rte_port* port);

/**
 *  Close the port 
 * 
 * @param pid 
 * 	port id which will be closed
 */
int rte_port_close(uint16_t pid, struct rte_port* port);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // _RT_ETH_H