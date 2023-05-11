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
#include "driver/rt_ethdev_core.h"
#include <string.h>
#include <rte_log.h>
#include "driver/rt_ethdev_generic.h"

/**
 * Store the configuration associated with each port
 */
struct port_config port_config[RTE_MAX_ETHPORTS];

/**
 * 	Store the configuration of ethdev layer
 */
struct ethdev_config ethdev_config;

/*
 * Probed Target Environment.
 */
struct rte_port *ports = NULL;	       /**< For all probed ethernet ports. */

struct port_config* port_get_config(void)
{
    return &port_config;
}

struct ethdev_config* ethdev_get_config(void)
{
    return &ethdev_config;
}

#define PORT_INFO_NAME "port_configuration"
struct rte_port* port_get_info(void)
{
    if (ports == NULL) {
        if (rte_eal_process_type() != RTE_PROC_PRIMARY)
            ports = rte_memzone_reserve_aligned(
                            PORT_INFO_NAME, 
                            sizeof(struct rte_port) * RTE_MAX_ETHPORTS,
                            0, 0, RTE_CACHE_LINE_SIZE);
    } else {
        ports = rte_memzone_lookup(PORT_INFO_NAME);
    }
    return ports;
}

static void ethdev_reset_cfg(struct ethdev_config* ethdev_cfg)
{
    memset(ethdev_cfg, 0, sizeof(*ethdev_cfg));
    ethdev_cfg->num_sockets = RTE_PARAM_UNSET;
    ethdev_cfg->num_cpuids = RTE_PARAM_UNSET;
    ethdev_cfg->logtype = RTE_PARAM_UNSET;
    ethdev_cfg->level = RTE_LOG_INFO;
    ethdev_cfg->mbuf_data_size_n = 1;
    ethdev_cfg->mbuf_data_size[0] = 1500;
    ethdev_cfg->mp_alloc_type = MP_ALLOC_NATIVE;
    ethdev_cfg->mp_create_type = MP_PER_SOCKET;
    ethdev_cfg->mb_mempool_cache = DEF_MBUF_CACHE;
}

static void port_reset_cfg(struct port_config* ports_cfg, unsigned int cnt)
{
    unsigned int i;
    
    memset(ports_cfg, 0, sizeof(*port_cfg) * cnt);
    for (i = 0; i < cnt; ++i) {
        struct port_config *port_cfg = &ports_cfg[i];
        port_cfg->ports_id = i;
        port_cfg->txring_numa = NUMA_NO_CONFIG;
        port_cfg->rxring_numa = NUMA_NO_CONFIG;
        port_cfg->nb_rxd = RX_DESC_DEFAULT;
        port_cfg->nb_txd = TX_DESC_DEFAULT;
        port_cfg->nb_rxq = 1;
        port_cfg->nb_txq = 1;
        port_cfg->rx_free_thresh = RTE_PARAM_UNSET;
        port_cfg->rx_drop_en = RTE_PARAM_UNSET;
        port_cfg->tx_free_thresh = RTE_PARAM_UNSET;
        port_cfg->tx_rs_thresh = RTE_PARAM_UNSET;
        port_cfg->rx_pthresh = RTE_PARAM_UNSET;
        port_cfg->tx_hthresh = RTE_PARAM_UNSET;
        port_cfg->rx_wthresh = RTE_PARAM_UNSET;
        port_cfg->tx_pthresh = RTE_PARAM_UNSET;
        port_cfg->tx_hthresh = RTE_PARAM_UNSET;
        port_cfg->tx_wthresh = RTE_PARAM_UNSET;
        port_cfg->lsc_interrupt = 0;
        port_cfg->no_link_check = 1;
        port_cfg->promiscuous_enable = 0;
    }
}

void rt_port_reset_config(void)
{
    struct ethdev_config* ethdev_cfg = ethdev_get_config();
    struct port_config* ports_cfg = port_get_config();

    ethdev_reset_cfg(ethdev_cfg);
    port_reset_cfg(ports_cfg);    
}
