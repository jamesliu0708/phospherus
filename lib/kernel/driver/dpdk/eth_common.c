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
#include "eth_common.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_cfgfile.h>

int
port_id_is_invalid(uint16_t port_id)
{
	uint16_t pid;

	if (port_id == (uint16_t)RTE_PORT_ALL)
		return 0;

	RTE_ETH_FOREACH_DEV(pid)
		if (port_id == pid)
			return 0;

	fprintf(stderr, "Invalid port %d\n", port_id);

	return 1;
}

int eth_dev_info_get_print_err(uint16_t port_id,
					struct rte_eth_dev_info *dev_info)
{
	int ret;

	ret = rte_eth_dev_info_get(port_id, dev_info);
	if (ret != 0)
		fprintf(stderr,
			"Error during getting device (port %u) info: %s\n",
			port_id, strerror(-ret));

	return ret;
}

int check_socket_id(uint32_t socket_id)
{
	// if (numa_available() < 0 || numa_max_node() > socket_id) 
	// 	return -1;
	return 0;
}
