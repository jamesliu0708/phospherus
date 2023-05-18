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
#ifndef _RTE_ETHDEV_CORE_H
#define _RTE_ETHDEV_CORE_H

#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include "rte_eth_config.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define RTE_PORT_ALL            (~(portid_t)0x0)

#define RTE_PORT_STOPPED        (uint16_t)0
#define RTE_PORT_STARTED        (uint16_t)1
#define RTE_PORT_CLOSED         (uint16_t)2
#define RTE_PORT_HANDLING       (uint16_t)3

#define RTE_PARAM_UNSET -1

enum {
#define MP_ALLOC_NATIVE_STR "native-alloc"
	MP_ALLOC_NATIVE, /**< allocate and populate mempool natively */
#define MP_ALLOC_ANON_STR "annon-alloc"
	MP_ALLOC_ANON,
#define MP_ALLOC_XMEM_STR "xmem-alloc"
	/**< allocate mempool natively, but populate using anonymous memory */
	MP_ALLOC_XMEM,
#define MP_ALLOC_XMEM_HUGE_STR "huge-alloc"
	/**< allocate and populate mempool using anonymous memory */
	MP_ALLOC_XMEM_HUGE,
#define MP_ALLOC_XBUF_STR "xbuf-alloc"
	/**< allocate and populate mempool using anonymous hugepage memory */
	MP_ALLOC_XBUF
	/**< allocate mempool natively, use rte_pktmbuf_pool_create_extbuf */
};

/**
 * The data structure associated with RX and TX packet burst statistics
 * that are recorded for each forwarding stream.
 */
struct pkt_burst_stats {
	unsigned int pkt_burst_spread[MAX_PKT_BURST + 1];
};

/** Information for a given RSS type. */
struct rss_type_info {
	const char *str; /**< Type name. */
	uint64_t rss_type; /**< Type value. */
};

/** RX queue configuration and state. */
struct port_rxqueue {
	struct rte_eth_rxconf conf;
	uint8_t state; /**< RTE_ETH_QUEUE_STATE_* value. */
	uint16_t lcore;	/**< local core rx queue runing on */
	struct rte_mempool	*mbp; /**< mempool allocate */
};

/** TX queue configuration and state. */
struct port_txqueue {
	struct rte_eth_txconf conf;
	uint8_t state; /**< RTE_ETH_QUEUE_STATE_* value. */
	uint16_t lcore;	/**< local core rx queue runing on */
	struct rte_mempool	*mbp; /**< mempool allocate */
};

/** Information for an extended statistics to show. */
struct xstat_display_info {
	// /** Supported xstats IDs in the order of xstats_display */
	// uint64_t *ids_supp;
	// size_t   ids_supp_sz;
	// uint64_t *prev_values;
	// uint64_t *curr_values;
	// uint64_t prev_ns;
	// bool	 allocated;
};

struct mbuf_pool_configure {
	/**< Shared mempool with all Ethernet device */
	uint32_t 	total_num_mbufs; /**< Mbuf data space size. */
	uint32_t 	mbuf_data_size_n; /**< Number of specified mbuf sizes. */
	uint16_t 	mbuf_data_size[MAX_SEGS_BUFFER_SPLIT]; /**< Mbuf data space size. */
	uint16_t	mb_mempool_cache;
	int			alloc_type; 
	int 		mp_flag;
};

/**
 * The data structure associated with each port property configuration.
 */
struct rte_ethlayer_configure {
	uint32_t 	log_type;
	uint32_t	log_level;
	uint8_t 	socket[RTE_MAX_NUMA_NODES];
	uint8_t		num_socket;

	struct mbuf_pool_configure gmbp;
};

struct rte_ethdev_configure {
	portid_t port_id;
	int selected;
	int kni_flag; /**< Flag to enable kni */

	uint8_t ex_mbp;
	struct mbuf_pool_configure mbp;

	/**< Ethernet device configuration. */
	struct rte_eth_rxmode rx_mode;
	struct rte_eth_txmode tx_mode;
	enum rte_eth_rx_mq_mode rx_mq_mode;

	uint16_t nb_rxd; /**< Number of queue rx desc number */
	uint16_t nb_txd; /**< Number of queue tx desc number */
	queueid_t nb_rxq; /**< Number of rx queue */
	queueid_t nb_txq; /**< Number of tx queue */

	uint16_t rx_free_thresh; //**< Configurable value of RX free threshold. */
	uint8_t rx_drop_en; /**< Configurable value of RX drop enable. */
	uint16_t tx_free_thresh; /**< Configurable value of TX free threshold. */
	uint16_t tx_rs_thresh; /**< Configurable value of TX RS bit threshold. */

	uint32_t eth_link_speed; /**< Used to set forced link speed */
	uint32_t max_rx_pkt_len;

	/*
	* Configurable values of RX and TX ring threshold registers.
	*/
	uint8_t rx_pthresh;
	uint8_t rx_hthresh;
	uint8_t rx_wthresh;
	uint8_t tx_pthresh;
	uint8_t tx_hthresh;
	uint8_t tx_wthresh;

	uint16_t  nb_rx_desc[RTE_MAX_QUEUES_PER_PORT+1]; /**< per queue rx desc number */
	uint16_t  nb_tx_desc[RTE_MAX_QUEUES_PER_PORT+1]; /**< per queue tx desc number */

	uint8_t lsc_interrupt;
	uint8_t no_link_check;

	int	promiscuous_enable;
};

/**
 * The data structure associated with each port.
 */
struct rte_port {
	struct rte_eth_dev_info dev_info;   /**< Device info + driver name */
	struct rte_eth_conf     dev_conf;   /**< Port configuration. */
	struct rte_ether_addr       eth_addr;   /**< Port ethernet address */
	struct rte_eth_stats    stats;      /**< Last port statistics */
	uint16_t                tso_segsz;  /**< Segmentation offload MSS for non-tunneled packets. */
	volatile uint16_t        port_status;    /**< port started or not */
	uint8_t                 need_setup;     /**< port just attached */
	uint8_t                 need_reconfig;  /**< need reconfiguring port or not */
	uint8_t                 need_reconfig_queues; /**< need reconfiguring queues or not */
	uint8_t                 rss_flag;   /**< enable rss or not */
	uint8_t                 dcb_flag;   /**< enable dcb */
	uint16_t                nb_rx_desc[RTE_MAX_QUEUES_PER_PORT+1]; /**< per queue rx desc number */
	uint16_t                nb_tx_desc[RTE_MAX_QUEUES_PER_PORT+1]; /**< per queue tx desc number */
	struct port_rxqueue     rxq[RTE_MAX_QUEUES_PER_PORT+1]; /**< per queue Rx config and state */
	struct port_txqueue     txq[RTE_MAX_QUEUES_PER_PORT+1]; /**< per queue Tx config and state */
	struct rte_ether_addr   *mc_addr_pool; /**< pool of multicast addrs */
	uint32_t                mc_addr_nb; /**< nb. of addr. in mc_addr_pool */
	queueid_t               queue_nb; /**< nb. of queues for flow rules */
	uint32_t                queue_sz; /**< size of a queue for flow rules */
	uint8_t                 slave_flag : 1, /**< bonding slave port */
				update_conf : 1; /**< need to update bonding device configuration */
	/**< metadata value to insert in Tx packets. */
	uint32_t		tx_metadata;
	const struct rte_eth_rxtx_callback *tx_set_md_cb[RTE_MAX_QUEUES_PER_PORT+1];
	/**< dynamic flags. */
	uint64_t		mbuf_dynf;
	const struct rte_eth_rxtx_callback *tx_set_dynf_cb[RTE_MAX_QUEUES_PER_PORT+1];
	struct xstat_display_info xstats_info;
};


extern int rte_eth_log_type;

/**
 * Get the internal port configuration structure.
 * 
 * @param pid 
 * @return struct rte_port_config* 
 */
struct rte_ethdev_configure  *rte_get_eth_config(uint16_t pid);

/**
 * Get the internal ethdev layer configuration structure.
 *
 * @return
 *   A pointer to the ethdev layer configuration structure.
 */
struct rte_ethlayer_configure *rte_gethdev_get_config(void);

/**
 * Get the internal configuration structure.
 *
 * @return
 *   A pointer to the port structure.
 */
struct rte_port *rte_eth_get_port(void);

/**
 * Set port config as default configuation
 */
void rte_port_reset_config(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif //_RTE_ETHDEV_CORE_H
