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
#ifndef _RT_ETHDEV_H
#define _RT_ETHDEV_H

#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mempool.h>
#include <rte_mbuf_dyn.h>
#include <rte_common.h>
#include <driver/rt_ethdev_config.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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
 * @param cfgfile
 *  configuration file path
 * @return int 
 *  - On success, zero.
 * 	- On failure, a negative value.
 */
int rt_ethdev_setup(const char* cfgfile);

/**
 * Start the port
 *  
 * @param pid 
 * @return int 
 */
int rt_port_start(portid_t pid);

/**
 *  Stop the port
 * 
 * @param pid 
 * 	port id which will be stopped
 */
void rt_port_stop(portid_t pid);

/**
 *  Close the port 
 * 
 * @param pid 
 * 	port id which will be closed
 */
void rt_port_close(portid_t pid);

/**
 *  Initialize port configuration
 * 
 * @param pid 
 * 	port id which configuration will be init
 * @return int
 * 	- On success, zero.
 * 	- On failure, a negative value.
 */
int rt_port_setup_config(portid_t pid);

/**
 * Open confif file and initialize the port configuration
 * 
 * @param profile 
 *  Config file name
 * @return int 
 *  - On sucess, zero
 *  - On failure, a negative value
 */
int rt_port_load_cfg(const char * profile);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // _RT_ETHDEV_H