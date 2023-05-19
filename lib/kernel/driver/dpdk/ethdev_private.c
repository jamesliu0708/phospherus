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

// Date: Wed Apr 27 16:56:45 CST 2023
#include "rte_eth_core.h"
#include <string.h>
#include <rte_log.h>

/**
 * Store the configuration associated with each port
 */
struct rte_ethdev_configure ethcfg[RTE_MAX_ETHPORTS];

/**
 * 	Store the configuration of ethdev layer
 */
struct rte_ethlayer_configure gethcfg;

/*
 * Probed Target Environment.
 */
struct rte_port *ports = NULL;	       /**< For all probed ethernet ports. */

struct rte_ethlayer_configure* rte_gethdev_get_config(void)
{
    return &gethcfg;
}

struct rte_ethdev_configure *rte_eth_get_config(uint16_t pid)
{
    if (pid >= RTE_MAX_ETHPORTS)    
        return NULL;
    return &ethcfg[pid];
}
