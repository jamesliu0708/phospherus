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
#include <rte_os_shim.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mempool.h>
#include <rte_mbuf_dyn.h>
#include <rte_common.h>
#include <driver/rt_ethdev_config.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define RTE_PORT_ALL            (~(portid_t)0x0)

#define RTE_PORT_STOPPED        (uint16_t)0
#define RTE_PORT_STARTED        (uint16_t)1
#define RTE_PORT_CLOSED         (uint16_t)2
#define RTE_PORT_HANDLING       (uint16_t)3

#define RTE_PMD_PARAM_UNSET -1

enum {
	MP_ALLOC_NATIVE, /**< allocate and populate mempool natively */
	MP_ALLOC_ANON,
	/**< allocate mempool natively, but populate using anonymous memory */
	MP_ALLOC_XMEM,
	/**< allocate and populate mempool using anonymous memory */
	MP_ALLOC_XMEM_HUGE,
	/**< allocate and populate mempool using anonymous hugepage memory */
	MP_ALLOC_XBUF
	/**< allocate mempool natively, use rte_pktmbuf_pool_create_extbuf */
};

enum {
	MP_PER_QUEUE,	/**< create mempool per rx/tx queue */
	MP_PER_CORE,	/**< creaate mempool per core*/
	MP_PER_SOCKET,	/**< create mempool per socket */
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
	lcoreid_t lcore;	/**< local core rx queue runing on */
	struct rte_mempool	*mbp; /**< mempool allocate */
};

/** TX queue configuration and state. */
struct port_txqueue {
	struct rte_eth_txconf conf;
	uint8_t state; /**< RTE_ETH_QUEUE_STATE_* value. */
	lcoreid_t lcore;	/**< local core rx queue runing on */
	struct rte_mempool	*mbp; /**< mempool allocate */
};

/** Information for an extended statistics to show. */
struct xstat_display_info {
	/** Supported xstats IDs in the order of xstats_display */
	uint64_t *ids_supp;
	size_t   ids_supp_sz;
	uint64_t *prev_values;
	uint64_t *curr_values;
	uint64_t prev_ns;
	bool	 allocated;
};

/**
 * The data structure associated with each port property configuration.
 */
struct port_config {
	portid_t ports_id;
	int		selected;
	int		probed;

	const struct rss_type_info rss_type_table[]; /**< An entry with a NULL type name terminates the list. */ 
	uint64_t rss_hf; /**< Receive Side Scaling (RSS) configuration. */
	
	char dynf_names[64][RTE_MBUF_DYN_NAMESIZE]; /**< Array that holds the name for each dynf. */
	
	uint8_t	port_numa; /**< Store specified sockets on which memory pool to be used by ports is allocated. */
	uint8_t rxring_numa; /**< Store specified sockets on which RX ring to be used by ports is allocated. */
	uint8_t txring_numa; /**< Store specified sockets on which TX ring to be used by ports is allocated. */
	
	/**< Ethernet device configuration. */
	struct rte_eth_rxmode rx_mode;
	struct rte_eth_txmode tx_mode;
	enum rte_eth_rx_mq_mode rx_mq_mode;

	uint16_t nb_rxd; /**< Number of queue rx desc number */
	uint16_t nb_txd; /**< Number of queue tx desc number */
	queueid_t nb_rxq; /**< Number of rx queue */
	queueid_t nb_txq; /**< Number of tx queue */

	int16_t rx_free_thresh; //**< Configurable value of RX free threshold. */
	int8_t rx_drop_en; /**< Configurable value of RX drop enable. */
	int16_t tx_free_thresh; /**< Configurable value of TX free threshold. */
	int16_t tx_rs_thresh; /**< Configurable value of TX RS bit threshold. */

	uint32_t eth_link_speed; /**< Used to set forced link speed */
	uint32_t max_rx_pkt_len;

	/*
	* Configurable values of RX and TX ring threshold registers.
	*/
	int8_t rx_pthresh;
	int8_t rx_hthresh;
	int8_t rx_wthresh;
	int8_t tx_pthresh;
	int8_t tx_hthresh;
	int8_t tx_wthresh;

	uint8_t lsc_interrupt;
	uint8_t no_link_check;

	int	promiscuous_enable;
};

struct ethdev_config {
	int8_t	num_sockets;
	int8_t	num_cpuids;
	unsigned int socket_ids[RTE_MAX_NUMA_NODES];
	unsigned int cpu_ids[RTE_MAX_LCORE];

	portid_t nb_ports; /**< Number of ethernet ports probed at init time. */
	portid_t  nb_cfg_ports; /**< Number of configured ports. */
	int			logtype; /**< Log type for ethdev logs */
	uint32_t	level;	/**< Log level for ethdev logs */

	uint32_t 	total_num_mbufs; /**< Mbuf data space size. */
	uint32_t 	mbuf_data_size_n; /**< Number of specified mbuf sizes. */
	uint16_t 	mbuf_data_size[MAX_SEGS_BUFFER_SPLIT]; /**< Mbuf data space size. */

	uint8_t 	mp_alloc_type; /**< Select mempool allocation type */
	uint8_t 	mp_create_type; /**< Select mempool creation type */
	uint32_t 	mb_mempool_cache; /**< Size of mbuf mempool cache. */
	uint16_t	mempool_flag; /**< Flag of mempool */
};

struct rt_eth_lcore {
	struct rte_mempool *mbp; /**< The mbuf pool to use by this core */
	lcoreid_t  cpuid_idx;    /**< index of logical core in CPU id table */
};

/**
 * The data structure associated with each port.
 */
struct rte_port {
	struct rte_eth_dev_info dev_info;   /**< Device info + driver name */
	struct rte_eth_conf     dev_conf;   /**< Port configuration. */
	struct rte_ether_addr       eth_addr;   /**< Port ethernet address */
	struct rte_eth_stats    stats;      /**< Last port statistics */
	unsigned int            socket_id;  /**< For NUMA support */
	uint16_t		parse_tunnel:1; /**< Parse internal headers */
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
} __rte_cache_aligned;

struct rt_eth_stream {
	/* "read-only" data */
	portid_t   rx_portid;   /**< port to poll for received packets */
	queueid_t  rx_queue;  /**< RX queue to poll on "rx_port" */
	portid_t   tx_portid;   /**< forwarding port of received packets */
	queueid_t  tx_queue;  /**< TX queue to send forwarded packets */
	bool       disabled;  /**< the stream is disabled and should not run */

	/* "read-write" results */
	uint64_t rx_packets;  /**< received packets */
	uint64_t tx_packets;  /**< received packets transmitted */

	uint64_t rx_bad_ip_csum ; /**< received packets has bad ip checksum */
	uint64_t rx_bad_l4_csum ; /**< received packets has bad l4 checksum */
	uint64_t rx_bad_outer_l4_csum;
	/**< received packets has bad outer l4 checksum */
	uint64_t rx_bad_outer_ip_csum;
};

/**
 * Store the configuration associated with each port
 */
extern struct port_config port_config[RTE_MAX_ETHPORTS];

/**
 * 	Store the configuration of ethdev layer
 */
extern struct ethdev_config ethdev_config;

/*
 * Probed Target Environment.
 */
extern struct rte_port *ports;	       /**< For all probed ethernet ports. */

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
int rt_eth_log_init(const char* logname, uint32_t level);

/**
 * 
 * 
 * @return int 
 */
int rt_ethdev_init(void);

int rt_start_port(portid_t pid);

void rt_port_reset_config(void);

/**
 *  Stop the port
 * 
 * @param pid 
 * 	port id which will be stopped
 */
void rt_stop_port(portid_t pid);

/**
 *  Close the port 
 * 
 * @param pid 
 * 	port id which will be closed
 */
void rt_close_port(portid_t pid);

/**
 *  Initialize port configuration
 * 
 * @param pid 
 * 	port id which configuration will be init
 * @return int
 * 	- On success, zero.
 * 	- On failure, a negative value.
 */
int rt_init_port_config(portid_t pid);

/**
 * Set port config as default configuation
 */
void rt_port_reset_config(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // _RT_ETHDEV_H