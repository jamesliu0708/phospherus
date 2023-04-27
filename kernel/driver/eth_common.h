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
#ifndef _RT_ETH_COMMON_H
#define _RT_ETH_COMMON_H

#include <driver/ethdev_config.h>

#define RT_ETHDEV_LOGNAME   ##rt_ethdev

#define EXTMEM_HEAP_NAME "extmem"

#define RT_ETHDEV_LOGTYPE (ethdev_config.logtype)

#define RT_ETHDEV_LOG(level, fmt, args...)  \
    rte_log(RTE_LOG_ ## level, RT_ETHDEV_LOGTYPE, "ethdev: " fmt, ## args)

int port_id_is_invalid(portid_t port_id);

int eth_dev_info_get_print_err(uint16_t port_id, struct rte_eth_dev_info *dev_info);

int check_socket_id(uint32_t socket_id);

/**
 * 
 * //todo
 * @param name 
 * @param mbuf_size 
 * @param nb_mbuf 
 * @param socket_id 
 * @return struct rte_mempool* 
 */
struct rte_mempool* rt_mktbuf_pool_create(const char* name, 
                        uint8_t mp_alloc_type,
                        unsigned int mempool_cache,
                        uint16_t mbuf_size, unsigned nb_mbuf, 
                        unsigned int socket_id);

#endif // _RT_ETH_COMMON_H