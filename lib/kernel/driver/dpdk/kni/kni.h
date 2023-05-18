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

// Date: Thur May 11 13:10:00 CST 2023
#ifndef _DRIVER_KNI_H
#define _DRIVER_KNI_H

#include <stdint.h>

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
    /* number of pkts received from NIC, and sent to KNI */
	uint64_t rx_packets;

	/* number of pkts received from NIC, but failed to send to KNI */
	uint64_t rx_dropped;

	/* number of pkts received from KNI, and sent to NIC */
	uint64_t tx_packets;

	/* number of pkts received from KNI, but failed to send to NIC */
	uint64_t tx_dropped;
};

struct rte_mbuf;
/**
 * @brief 
 * 
 * @param pkts 
 * @param num 
 */
void kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num);

#endif // _DRIVER_KNI_H