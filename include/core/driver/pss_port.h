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

// Date: Thur May 17 14:13:15 CST 2023
#ifndef _PSS_PORT_H
#define _PSS_PORT_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_common.h>
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
struct pss_port;

struct pss_pktbuf {
    void *pbuf; /**< Pointer to internal data buf */
    uint32_t pktlen; /**< Length of data payload */
    void *payload; /**< Pointern to data payload */
};

/**
 * Retrieve input packets from a receive queue of an Ethernet device.
 */
typedef uint16_t (*pkt_rx_burst_t)(struct pss_port* port, 
                            uint16_t queue_id, struct pss_pktbuf** pkt, 
                            const unsigned int nb_pkts);
/**
 * Send output packets on a transmit queue of an Ethernet device.
 */
typedef uint16_t (*pkt_tx_burst_t)(struct pss_port* port,
                            uint16_t queue_id, struct pss_pktbuf** pkt,
                            const unsigned int nb_pkts);

/**
 * Alloc packet buffer used for receive or transmit on queue for dma on an Ethernet device 
 */
typedef uint16_t (*rxtx_pkt_alloc_t)(struct pss_port* port,
                            uint16_t queue_id, struct pss_pktbuf** pkt,
                            const unsigned int nb_pkts, void* flag);

/**
 * Free packet buffer used for receive or transmit on queue for dma on an Ethernet device 
 */
typedef void (*rxtx_pkt_free_t)(struct pss_port* port,
                            uint16_t queue_id, struct pss_pktbuf** pkt,
                            const unsigned int nb_pkt, void* flag);

/**
 * Filter the buffer stream for receive pkts
 * 
 * @return typedef 
 */
typedef bool (*rxtx_pkt_filter_t)(struct pss_port* port,
                            uint16_t queue_id, const void* pkt);

struct pss_port_ops {
    /** PMD receive function. */
    pkt_rx_burst_t pkt_rx_burst;
    /** Filter recv package */
    rxtx_pkt_filter_t pkt_filter;
    /** PMD transmit function. */
    pkt_tx_burst_t pkt_tx_burst;
    /** Alloc package */
    rxtx_pkt_alloc_t pkt_alloc;
    /** Free package */
    rxtx_pkt_free_t pkt_free;    
};

#define PTE_PORT_NAME_LEN 100
struct pss_port {
    const char name[100]; /**< Device Driver name. */
    struct rte_memzone* mz;
    uint16_t port_id;   /**< Index to bound host interface, or 0 if none. */
    struct pss_port_ops ops;   /**< Device operation */
    unsigned int socket_id; /**< For NUMA support */
    void * data;
};

/**
 * Do something preparation to init Ethernet device
 */
bool pss_ethlayer_prepare(void);

/**
 * Setup dev port
 *  Load the configuration from a file and initialize dev port
 * @param ifname
 *  Ethernet device name
 * @return int 
 *  Pointer to port structure
 */
struct pss_port* pss_port_setup(const char* ifname);

/**
 * Search a port from its name
 * 
 * @param ifname 
 *  The name of the Ethernet device
 * @return struct pss_port* 
 *  The pointer to the port matching the ifname, or NULL if not found,
 */
struct pss_port* pss_port_lookup(const char* ifname);

/**
 * Cleanup the rte port environment
 * 
 * @param port 
 *  Pointer to port structure should cleanup
 */
void pss_port_cleanup(struct pss_port* port);


__rte_always_inline uint16_t pss_pkt_rx_burst(struct pss_port* port, 
                            uint16_t queue_id, struct pss_pktbuf** pkt, 
                            const unsigned int nb_pkts) 
{
    return port->ops.pkt_rx_burst(port, queue_id, pkt, nb_pkts);
}

__rte_always_inline uint16_t pss_pkt_tx_burst(struct pss_port* port,
                            uint16_t queue_id, struct pss_pktbuf** pkt,
                            const unsigned int nb_pkts) 
{
    return port->ops.pkt_tx_burst(port, queue_id, pkt, nb_pkts);
}

__rte_always_inline uint16_t pss_rxtx_pkt_alloc(struct pss_port* port,
                            uint16_t queue_id, struct pss_pktbuf** pkt,
                            const unsigned int nb_pkts, void* flag) 
{
    return port->ops.pkt_alloc(port, queue_id, pkt, nb_pkts, flag);
}

__rte_always_inline void pss_rxtx_pkt_free(struct pss_port* port,
                            uint16_t queue_id, struct pss_pktbuf** pkt,
                            const unsigned int nb_pkt, void* flag)
{
    return port->ops.pkt_free(port, queue_id, pkt, nb_pkt, flag);
}

__rte_always_inline void pss_set_pkt_filter(struct pss_port* port, 
                            rxtx_pkt_filter_t filter)
{
    port->ops.pkt_filter = filter;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // _PSS_PORT_H