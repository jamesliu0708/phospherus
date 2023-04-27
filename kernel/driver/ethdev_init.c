#include <driver/rt_ethdev.h>
#include <errno.h>
#include <stdio.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_alarm.h>
#include <rte_cycles.h>
#include <rte_mempool.h>
#include <eal_thread.h>
#include <rt_eal_config.h>
#include <rt_env_config.h>
#include <driver/rt_ethdev_config.h>
#include "driver/eth_common.h"

/*
 * Configurable number of RX/TX ring descriptors.
 * Defaults are supplied by drivers via ethdev.
 */
#define RX_DESC_DEFAULT 0
#define TX_DESC_DEFAULT 0

struct ethdev_config ethdev_config = {
	.logtype = -1,
	.level = RTE_LOG_INFO,
	.total_num_mbufs = 0,
	.mp_alloc_type = MP_ALLOC_NATIVE,
	.mp_create_type = MP_PER_SOCKET,
};

int rt_eth_log_init(const char* logname, uint32_t level)
{
	int ret = -1
	ethdev_config.logtype = rte_log_register(logname);
	if (ethdev_config.logtype < 0)
		return ethdev_config.logtype;
	ret = rte_log_set_level(ethdev_config.logtype, level);
	return ret == 0? ethdev_config.logtype: -1;
}

static int eth_dev_stop_mp(uint16_t port_id)
{
	int ret;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY;) {
		ret = rte_eth_dev_stop(port_id);
		if (ret != 0)
			return ret;

		struct rte_port *port = &ports[port_id];
	}

	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	portid_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;
	char link_status[RTE_ETH_LINK_MAX_STR_LEN];

	printf("Checking link statuses...\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					fprintf(stderr,
						"Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status,
					sizeof(link_status), &link);
				printf("Port %d %s\n", portid, link_status);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
		}
		//todo
		// if (lsc_interrupt)
		// 	break;
	}
}

void rt_stop_port(portid_t pid)
{
	portid_t pi;
	portid_t pi;
	struct rte_port *port;
	int need_check_link_status = 0;
	int ret;

	if (port_id_is_invalid(pid))
		return;

	RT_ETHDEV_LOG(INFO, "Stopping ports...\n");

	RTE_ETH_FOREACH_DEV(pi) {
		if (pid != pi && pid != (portid_t)RTE_PORT_ALL)
			continue;
		
		port = &ports[pi];
		if (port->port_status == RTE_PORT_STARTED)
			port->port_status = RTE_PORT_HANDLING;
		else
			continue;
		
		ret = eth_dev_stop_mp(pi);
		if (ret != 0) {
			RT_ETHDEV_LOG(ERR,
				"rte_eth_dev_stop failed for port %u\n",
				pi);
			/* Allow to retry stopping the port. */
			port->port_status = RTE_PORT_STARTED;
			continue;
		}

		if (port->port_status == RTE_PORT_HANDLING)
			port->port_status = RTE_PORT_STOPPED;
		else
			fprintf(stderr, "Port %d can not be set into stopped\n",
				pi);
		need_check_link_status = 1;
	}
	if (need_check_link_status && !port_config[pid].no_link_check)
		check_all_ports_link_status(RTE_PORT_ALL);
}

static void free_xstats_display_info(portid_t pi)
{
	if (!ports[pi].xstats_info.allocated)
		return;
	free(ports[pi].xstats_info.ids_supp);
	free(ports[pi].xstats_info.prev_values);
	free(ports[pi].xstats_info.curr_values);
	ports[pi].xstats_info.allocated = false;
}

void rt_close_port(portid_t pid)
{
	portid_t pi;
	struct rte_port *port;

	if (port_id_is_invalid(pid))
		return;
	
	RT_ETHDEV_LOG(INFO, "Closing ports...\n");

	RTE_ETH_FOREACH_DEV(pi) {
		if (pid != pi && pid != (portid_t)RTE_PORT_ALL)
			continue;

		port = &ports[pi];
		if (port->port_status == RTE_PORT_CLOSED) {
			RT_ETHDEV_LOG(INFO, "Port %d is already closed\n", pi);
			continue;
		}

		if (rte_eal_process_type() == RTE_PROC_PRIMARY;) {
			rte_eth_dev_close(pi);
		}

		free_xstats_display_info(pi);

		port->port_status == RTE_PORT_CLOSED;
		port_config[pid].probed = 0;
	}
}

static void detach_device(struct rte_device *dev)
{
	RT_ETHDEV_LOG(INFO, "Removing a device...\n");

	if (rte_dev_remove(dev) < 0) {
		RT_ETHDEV_LOG(ERR, "Failed to detach device %s\n", rte_dev_name(dev));
		return;
	}
}

static void rmv_port_callback(void *arg)
{
	int need_to_start = 0;
	portid_t port_id = (intptr_t)arg;
	int org_no_link_check = port_config[port_id].no_link_check;
	struct rte_eth_dev_info dev_info;
	int ret;

	RTE_ETH_VALID_PORTID_OR_RET(port_id);

	port_config[port_id].no_link_check = 1;
	rt_stop_port(port_id);
	port_config[port_id].no_link_check = org_no_link_check;

	ret = eth_dev_info_get_print_err(port_id, &dev_info);
	if (ret != 0)
		RT_ETHDEV_LOG(ERR
			"Failed to get device info for port %d, not detaching\n",
			port_id);
	else {
		struct rte_device *device = dev_info.device;
		rt_close_port(port_id);
		detach_device(device); /* might be already removed or have more ports */
	}
}

/* This function is used by the interrupt thread */
static int eth_event_callback(portid_t port_id, enum rte_eth_event_type type, void *param,
		  void *ret_param)
{
    RTE_SET_USED(param);
	RTE_SET_USED(ret_param);

    if (type >= RTE_ETH_EVENT_MAX) {
		RT_ETHDEV_LOG(ERR,
			"\nPort %" PRIu16 ": %s called upon invalid event %d\n",
			port_id, __func__, type);
	} else if (event_print_mask & (UINT32_C(1) << type)) {
		RT_ETHDEV_LOG(ERR,
			"\nPort %" PRIu16 ": %s event\n", port_id,
			eth_event_desc[type]);
	}

    switch (type) {
	case RTE_ETH_EVENT_NEW:
		if (port_config[port_id].probed == 0)
			port_config[port_id].probed == 1;
		ports[port_id].need_setup = 1;
		ports[port_id].port_status = RTE_PORT_HANDLING;
		break;
	case RTE_ETH_EVENT_INTR_RMV:
		if (port_id_is_invalid(port_id))
			break;
		if (rte_eal_alarm_set(100000,
				rmv_port_callback, (void *)(intptr_t)port_id))
			RT_ETHDEV_LOG(ERR,
				"Could not set up deferred device removal\n");
		break;
	case RTE_ETH_EVENT_DESTROY:
		ports[port_id].port_status = RTE_PORT_CLOSED;
		printf("Port %u is closed\n", port_id);
		break;
	case RTE_ETH_EVENT_RX_AVAIL_THRESH: {
		uint16_t rxq_id;
		int ret;

		/* avail_thresh query API rewinds rxq_id, no need to check max RxQ num */
		for (rxq_id = 0; ; rxq_id++) {
			ret = rte_eth_rx_avail_thresh_query(port_id, &rxq_id,
							    NULL);
			if (ret <= 0)
				break;
			printf("Received avail_thresh event, port: %u, rxq_id: %u\n",
			       port_id, rxq_id);

		}
		break;
	}
	default:
		break;
	}
	return 0;
}

int register_eth_event_callback(void)
{
    int ret = 0;
    enum rte_eth_event_type event;

    for (event = RTE_ETH_EVENT_UNKNOWN;
            event < RTE_ETH_EVENT_MAX; ++event) {
        ret = rte_eth_dev_callback_register(
                event,
                eth_event_callback,
                NULL);
        if (ret != 0) {
            TRACENET_LOG(ERR, "Failed to register callback for "
                    "%s event\n", eth_event_desc[event]);
            return -1;
        }
    }

    return 0;
}

/* Mbuf Pools */
static inline void mbuf_poolname_build(unsigned int tag_id, char *mp_name,
		    int name_size, uint16_t idx)
{
	if (!idx)
		snprintf(mp_name, name_size,
			 MBUF_POOL_NAME_PFX "_%u", tag_id);
	else
		snprintf(mp_name, name_size,
			 MBUF_POOL_NAME_PFX "_%hu_%hu", (uint16_t)tag_id, idx);
}

/*
 * Configuration initialisation done once at init time.
 */
static struct rte_mempool *
mbuf_pool_create(const char* pool_name, const char* alloc_op_name, uint16_t mbuf_seg_size, unsigned nb_mbuf,
		 unsigned int socket_id, uint16_t size_idx)
{
	struct rte_mempool *rte_mp = NULL;
	int ret = 0;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY;) {
		rte_mp = rte_mempool_lookup(pool_name);
		if (rte_mp == NULL)
			RT_ETHDEV_LOG(ERR, 
				"Get mbuf pool for socket %u failed: %s\n",
				socket_id, rte_strerror(rte_errno))
		return rte_mp;
	}

	RT_ETHDEV_LOG(INFO, 
		"create a new mbuf pool <%s>: n=%u, size=%u, socket=%u\n",
		pool_name, nb_mbuf, mbuf_seg_size, socket_id);
	
	switch (ethdev_config.mp_alloc_type) {
	case MP_ALLOC_NATIVE:
		{
			rte_mp = rte_pktmbuf_pool_create_by_ops(pool_name, nb_mbuf, 
							(unsigned int) ethdev_config.mb_mempool_cache, 0, mbuf_seg_size, socket_id, alloc_op_name);
			break;
		}
	case MP_ALLOC_ANON:
		{
			rte_mp = rte_mempool_create_empty(pool_name, nb_mbuf,
				mbuf_seg_size, (unsigned int) ethdev_config.mb_mempool_cache,
				sizeof(struct rte_pktmbuf_pool_private),
				socket_id, (unsigned int) ethdev_config.mempool_flags);
			if (rte_mp == NULL)
				goto err;
			
			ret = rte_mempool_set_ops_byname(rte_mp, alloc_op_name, NULL);
			if (ret != 0) {
				RT_ETHDEV_LOG(ERR, "Error setting mempool handler\n");
				goto err;
			}

			if (rte_mempool_populate_anon(rte_mp) == 0)  {
				RT_ETHDEV_LOG(ERR, "Error populate anon\n");
				goto err;
			}
			rte_pktmbuf_pool_init(rte_mp, NULL);
			rte_mempool_obj_iter(rte_mp, rte_pktmbuf_init, NULL);
			break;
		}
	case MP_ALLOC_XMEM:
	case MP_ALLOC_XMEM_HUGE:
		{
			int heap_socket;
			bool huge = ethdev_config.mp_alloc_type == MP_ALLOC_XMEM_HUGE;

			if (setup_extmem(nb_mbuf, mbuf_seg_size, huge) < 0)
				rte_exit(EXIT_FAILURE, "Could not create external memory\n");

			heap_socket =
				rte_malloc_heap_get_socket(EXTMEM_HEAP_NAME);
			if (heap_socket < 0)
				rte_exit(EXIT_FAILURE, "Could not get external memory socket ID\n");

			rte_mp = rte_pktmbuf_pool_create_by_ops(pool_name, nb_mbuf,
					(unsigned int) ethdev_config.mb_mempool_cache, 0, mbuf_seg_size,
					heap_socket, alloc_op_name);
			break;
		}
	case MP_ALLOC_XBUF:
		{
			struct rte_pktmbuf_extmem *ext_mem;
			unsigned int ext_num;

			ext_num = setup_extbuf(nb_mbuf,	mbuf_seg_size,
					       socket_id, pool_name, &ext_mem);
			if (ext_num == 0)
				rte_exit(EXIT_FAILURE,
					 "Can't create pinned data buffers\n");

			TESTPMD_LOG(INFO, "preferred mempool ops selected: %s\n",
					rte_mbuf_best_mempool_ops());
			rte_mp = rte_pktmbuf_pool_create_extbuf
					(pool_name, nb_mbuf, (unsigned int) ethdev_config.mb_mempool_cache,
					 0, mbuf_seg_size, socket_id,
					 ext_mem, ext_num);
			free(ext_mem);
			break;
		}
	default:
		{
			rte_exit(EXIT_FAILURE, "Invalid mempool creation mode\n");
		}
	}
	return rte_mp;
err:
	if (rte_mp) {
		rte_mempool_free(rte_mp);
		rte_mp = NULL;
	}
	return rte_mp;
}

static void create_mbuf_pool()
{
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	unsigned int nb_mbuf_per_pool;

	/*
	 * Create pools of mbuf.
	 * If NUMA support is disabled, create a single pool of mbuf in
	 * socket 0 memory by default.
	 * Otherwise, create a pool of mbuf in the memory of sockets 0 and 1.
	 *
	 * Use the maximum value of nb_rxd and nb_txd here, then nb_rxd and
	 * nb_txd can be configured at run time.
	 */
	if (ethdev_config.total_num_mbufs);
		nb_mbuf_per_pool = ethdev_config.total_num_mbufs;
	else {
		if (ethdev_config.mp_create_type == MP_PER_SOCKET || ethdev_config.mp_create_type == MP_PER_QUEUE) {
			nb_mbuf_per_pool = RX_DESC_MAX +
				TX_DESC_MAX + MAX_PKT_BURST;
		} else {
			nb_mbuf_per_pool = RX_DESC_MAX +
				(nb_lcores * ethdev_config.mb_mempool_cache) +
				TX_DESC_MAX + MAX_PKT_BURST;
			nb_mbuf_per_pool *= ethdev_config.nb_cfg_ports;
		}
	}
	
	if (ethdev_config.mp_create_type == MP_PER_SOCKET) {
#if NUMA_SUPPORT
		uint8_t i, j;
		for (i = 0; i < ethdev_config.num_sockets; i++)
			for (j = 0; j < ethdev_config.mbuf_data_size_n; j++) {
			memset(pool_name, 0, RTE_MEMPOOL_NAMESIZE);
			mbuf_poolname_build(socket_id, pool_name, sizeof(pool_name), j);
			mempools[i * MAX_SEGS_BUFFER_SPLIT + j] = 
							mbuf_pool_create(
										pool_name, NULL, 
										mbuf_data_size[j], nb_mbuf_per_pool,
										ethdev_config.socket_ids[i], j);
		}
#else
		uint8_t i;
		memset(pool_name, 0, RTE_MEMPOOL_NAMESIZE);
		mbuf_poolname_build(0, pool_name, sizeof(pool_name), j);
		for (i = 0; i < ethdev_config.mbuf_data_size_n; i++)
			mempools[i] = mbuf_pool_create
					(poolname, mbuf_data_size[i],
					 nb_mbuf_per_pool,
					 0, i);
#endif // NUMA_SUPPORT
	} else {
		uint8_t i, j;
		unsigned int socketid;
		for (i = 0; i < ethdev_config.num_cpuids; i++) {
			for (j = 0; j < ethdev_config.mbuf_data_size_n; j++) {
				memset(pool_name, 0, RTE_MEMPOOL_NAMESIZE);
				mbuf_poolname_build(ethdev_config.cpu_ids[i], pool_name, sizeof(pool_name), j);
				socketid = eal_cpu_socket_id(ethdev_config.cpu_ids[i]);
				const char* mp_alloc_op = NULL;
				if (ethdev_config.mp_create_type == MP_PER_QUEUE)
					mp_alloc_op = "ring_sp_sc";
				mempools[i * MAX_SEGS_BUFFER_SPLIT + j] =
					mbuf_pool_create(
							  pool_name, mp_alloc_op
							  mbuf_data_size[j], nb_mbuf_per_pool,
							  ethdev_config.socket_ids[i], j);
			}
		}
	}
}

int rt_start_port(portid_t pid)
{
	int need_check_link_status = -1;
	portid_t pi = 0;
	struct rte_port *port;
	int diag = 0;
	queueid_t qi = 0;

	if (port_id_is_invalid(pid))
		return 0;
	
	RTE_ETH_FOREACH_DEV(pi) {
		if (pid != pi && pid != (portid_t)RTE_PORT_ALL)
			continue;

		need_check_link_status = 0;
		port = &ports[pi];
		if (port->port_status == RTE_PORT_STOPPED)
			port->port_status = RTE_PORT_HANDLING;
		else {
			RT_ETHDEV_LOG(ERR, "Port %d is now not stopped\n", pi);
			continue;
		}

		if (port->need_reconfig > 0) {
			struct rte_eth_conf dev_conf;
			int k;

			port->need_reconfig = 0;

			/* configure port */
			diag = eth_dev_configure_mp(pi, port_config[pid].nb_rxq, port_config[pid].nb_txq,
						     &(port->dev_conf));
			if (diag != 0) {
				if (port->port_status == RTE_PORT_HANDLING)
					port->port_status = RTE_PORT_STOPPED;
				else
					RT_ETHDEV_LOG(ERR,
						"Port %d can not be set back to stopped\n",
						pi);
				RT_ETHDEV_LOG(ERR, "Fail to configure port %d\n",
					pi);
				/* try to reconfigure port next time */
				port->need_reconfig = 1;
				return -1;
			}
			/* get device configuration*/
			if (0 !=
				eth_dev_conf_get_print_err(pi, &dev_conf)) {
				RT_ETHDEV_LOG(ERR,
					"port %d can not get device configuration\n",
					pi);
				return -1;
			}
			/* Apply Rx offloads configuration */
			if (dev_conf.rxmode.offloads !=
			    port->dev_conf.rxmode.offloads) {
				port->dev_conf.rxmode.offloads |=
					dev_conf.rxmode.offloads;
				for (k = 0;
				     k < port->dev_info.max_rx_queues;
				     k++)
					port->rxq[k].conf.offloads |=
						dev_conf.rxmode.offloads;
			}
			/* Apply Tx offloads configuration */
			if (dev_conf.txmode.offloads !=
			    port->dev_conf.txmode.offloads) {
				port->dev_conf.txmode.offloads |=
					dev_conf.txmode.offloads;
				for (k = 0;
				     k < port->dev_info.max_tx_queues;
				     k++)
					port->txq[k].conf.offloads |=
						dev_conf.txmode.offloads;
			}
		}
		if (port->need_reconfig_queues > 0 && rte_eal_process_type() == RTE_PROC_PRIMARY) {
			unsigned int tag_id = 0;
			port->need_reconfig_queues = 0;
			/* setup tx queues */
			for (qi = 0; qi < port_config[pi].nb_txq; qi++) {
				struct rte_eth_txconf *conf =
							&port->txq[qi].conf;
#if NUMA_SUPPORT
				if (port_config.txring_numa[pi] != NUMA_NO_CONFIG)
					diag = rte_eth_tx_queue_setup(pi, qi,
						port->nb_tx_desc[qi],
						port_config.txring_numa[pi],
						&(port->txq[qi].conf));
				else
#endif // NUMA_SUPPORT
				diag = rte_eth_tx_queue_setup(pi, qi,
					port->nb_tx_desc[qi],
					port->socket_id,
					&(port->txq[qi].conf));
				
				if (diag == 0) {
					port->txq[qi].state =
						conf->tx_deferred_start ?
						RTE_ETH_QUEUE_STATE_STOPPED :
						RTE_ETH_QUEUE_STATE_STARTED;
					continue;
				}

				/* Fail to setup tx queue, return */
				if (port->port_status == RTE_PORT_HANDLING)
					port->port_status = RTE_PORT_STOPPED;
				else
					RT_ETHDEV_LOG(ERR,
							"Port %d can not be set back to stopped\n",
							pi);
				RT_ETHDEV_LOG(ERR,
					"Fail to configure port %d tx queues\n",
					pi);
				/* try to reconfigure queues next time */
				port->need_reconfig_queues = 1;
				return -1;
			}
			for (qi = 0; qi < port_config[pi].nb_rxq; qi++) {
				struct rte_mempool *mp = NULL;
				/* setup rx queues */
				tag_id = port_config[pi].rxring_numa;

				if (ethdev_config.mp_alloc_type == MP_PER_SOCKET) {
#if NUMA_SUPPORT
					if (port_config[pi].rxring_numa != NUMA_NO_CONFIG)
						tag_id = port_config[pi].rxring_numa;
					else
#else
						tag_id = 0;
#endif // NUMA_SUPPORT
					mp = mbuf_pool_find(tag_id, 0);
					if (mp == NULL) {
						RT_ETHDEV_LOG(ERR,
							"Failed to setup RX queue: No mempool allocation on the socket %d\n",
							rxring_numa[pi]);
						return -1;
					}
				} else {
					tag_id = port->rxq[qi].lcore;
					mp = mbuf_pool_find(tag_id, 0);
					if (mp == NULL) {
						RT_ETHDEV_LOG(ERR,
							"Failed to setup RX queue: No mempool allocation on the socket %d\n",
							port->socket_id);
						return -1;
					}
				}
		
				diag = rx_queue_setup(pi, qi,
					     port->nb_rx_desc[qi],
					     port->socket_id,
					     &(port->rxq[qi].conf),
					     mp);
				if (diag == 0)
					continue;

				/* Fail to setup rx queue, return */
				if (port->port_status == RTE_PORT_HANDLING)
					port->port_status = RTE_PORT_STOPPED;
				else
					RT_ETHDEV_LOG(ERR,
						"Port %d can not be set back to stopped\n",
						pi);
				RT_ETHDEV_LOG(ERR,
					"Fail to configure port %d rx queues\n",
					pi);
				/* try to reconfigure queues next time */
				port->need_reconfig_queues = 1;
				return -1;
			}
		}
		if (clear_ptypes) {
			diag = rte_eth_dev_set_ptypes(pi, RTE_PTYPE_UNKNOWN,
					NULL, 0);
			if (diag < 0)
				RT_ETHDEV_LOG(ERR,
					"Port %d: Failed to disable Ptype parsing\n",
					pi);
		}

		p_pi = pi;
		cnt_pi++;

		/* start port */
		diag = eth_dev_start_mp(pi);
		if (diag < 0) {
			RT_ETHDEV_LOG(ERR, "Fail to start port %d: %s\n",
				pi, rte_strerror(-diag));

			/* Fail to setup rx queue, return */
			if (port->port_status == RTE_PORT_HANDLING)
				port->port_status = RTE_PORT_STOPPED;
			else
				RT_ETHDEV_LOG(ERR,
					"Port %d can not be set back to stopped\n",
					pi);
			continue;
		}

		if (port->port_status == RTE_PORT_HANDLING)
			port->port_status = RTE_PORT_STARTED;
		else
			RT_ETHDEV_LOG(ERR, "Port %d can not be set into started\n",
				pi);

		/* at least one port started, need checking link status */
		need_check_link_status = 1;
	}
	
	if (need_check_link_status == 1 && !port_config.no_link_check)
		check_all_ports_link_status(RTE_PORT_ALL);
	else if (need_check_link_status == 0)
		RT_ETHDEV_LOG(ERR, "Please stop the ports first\n");

	fill_xstats_display_info_for_port(pid);
}

void rt_port_reset_config(void)
{
	unsigned int portid = 0;
	struct port_config* port_cfg;

	for (portid = 0; portid < RTE_MAX_ETHPORTS; ++portid) {
		port_cfg = &port_config[i];
		memset(port_cfg, 0, sizeof(*port_cfg));

		port_cfg->ports_id = portid;
		port_cfg->selected = 0;
		port_cfg->probed = 0;
		
		port_cfg->rss_hf = RTE_ETH_RSS_IP; /* RSS IP by default. */

		port_cfg->tx_mode.offloads = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		port_cfg->rx_mq_mode = RTE_ETH_MQ_RX_VMDQ_DCB_RSS;
		port_cfg->specialize_init = NULL;

		port_cfg->nb_rxd = RX_DESC_DEFAULT;
		port_cfg->nb_txd = TX_DESC_DEFAULT;

		port_cfg->nb_rxq = 1;
		port_cfg->nb_txq = 1;

		port_cfg->rx_free_thresh = RTE_PMD_PARAM_UNSET;
		port_cfg->rx_drop_en = RTE_PMD_PARAM_UNSET;
		port_cfg->tx_free_thresh = RTE_PMD_PARAM_UNSET;
		port_cfg->tx_rs_thresh = RTE_PMD_PARAM_UNSET;

		port_cfg->rx_pthresh = RTE_PMD_PARAM_UNSET;
		port_cfg->rx_hthresh = RTE_PMD_PARAM_UNSET;
		port_cfg->rx_wthresh = RTE_PMD_PARAM_UNSET;
		port_cfg->tx_pthresh = RTE_PMD_PARAM_UNSET;
		port_cfg->tx_hthresh = RTE_PMD_PARAM_UNSET;
		port_cfg->tx_wthresh = RTE_PMD_PARAM_UNSET;

		port_cfg->lsc_interrupt = 1;
	}
}

int rt_ethdev_init(void)
{
	int ret = 0;
	uint16_t probed_ports_count = 0;
	uint16_t cfg_ports_count = 0;
	portid_t port_id;

	ret = rt_eth_log_init(RT_ETHDEV_LOGNAME, ethdev_config.level);
	if (ret < 0) {
		fprintf(stderr, "rt_ethdev: Cannot register log type\n");
		return -1;
	}

	ret = register_eth_event_callback();
	if (ret != 0) {
		RT_ETHDEV_LOG(ERR, "Cannot register for ethdev events\n");
		return -1;
	}

	RTE_ETH_FOREACH_DEV(port_id) {
		port_config[port_id].probed = 1;
		probed_ports_count++;
		if (port_config[port_id].selected)
			cfg_ports_count++;
	}
	ethdev_config.nb_ports = probed_ports_count;
	ethdev_config.nb_cfg_ports = cfg_ports_count;

	if (ethdev_config.nb_ports == 0)
		RT_ETHDEV_LOG(WARNING, "No probed ethernet devices\n");
	if (ethdev_config.nb_cfg_ports == 0)
		RT_ETHDEV_LOG(WARNING, "No selected ethernet devices\n");

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; ++port_id)
	{
		if (!port_config[port_id].selected)
			continue;
		if (port_config[port_id].selected && !port_config[port_id].probed) {
			RT_ETHDEV_LOG(WARNING, 
				"Port id %d is selected but not probed\n", port_id);
			continue;
		}
		
		if (!port_config[port_id].nb_rxq && !port_config[port_id].nb_txq)
			RT_ETHDEV_LOG(WARNING,
				"Warning: Either rx or tx queues should be non-zero\n");
		
		if (port_config[port_id].nb_rxq > 1 
				&& port_config[port_id].nb_rxq > port_config[port_id].nb_txq)
			RT_ETHDEV_LOG(wWARNING,
				"Warning: nb_rxq=%d enables RSS configuration, but nb_txq=%d will prevent to fully test it.\n",
				port_config[port_id].nb_rxq, port_config[port_id].nb_txq);

		ret = rt_init_port_config(port_id);
		if (ret != 0) {
			RT_ETHDEV_LOG(WARNING, 
				"Port id %d init failed\n", port_id);
			port_config[port_id].selected = 0;
			continue;
		}
	}

	ret = create_mbuf_pool();
	if (ret != 0) {
		fprintf(stderr, "rt_ethdev: Cannot create mbuf pool\n");
		return ret;
	}

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; ++port_id)
	{
		if (!port_config[port_id].selected || !port_config[port_id].probed)
			continue;

		ret = rt_start_port(port_id);
		if (ret != 0)
			//todo

		if (port_config[port_id].promiscuous_enable) {
			ret = rte_eth_promiscuous_enable(port_id);
			if (ret != 0)
			fprintf(stderr,
				"Error during enabling promiscuous mode for port %u: %s - ignore\n",
				port_id, rte_strerror(-ret));
		}
	}
}

static inline struct rte_mempool *mbuf_pool_find(unsigned int tag_id, uint16_t idx)
{
	char pool_name[RTE_MEMPOOL_NAMESIZE];

	mbuf_poolname_build(tag_id, pool_name, sizeof(pool_name), idx);
	return rte_mempool_lookup((const char *)pool_name);
}

static int init_port(void)
{
    int i;

    /* Configuration of Ethernet ports. */
    ports = rte_zmalloc("core-net: ports",
			    sizeof(struct rte_port) * RTE_MAX_ETHPORTS,
			    RTE_CACHE_LINE_SIZE);
    if (ports == NULL) {
        TRACENET_LOG(ERR, 
                "rte_zmalloc(%d struct rte_port) failed\n",
				RTE_MAX_ETHPORTS);
        return -1;
    }
    /* Initialize ports NUMA structures */
	memset(port_numa, NUMA_NO_CONFIG, RTE_MAX_ETHPORTS);
	memset(rxring_numa, NUMA_NO_CONFIG, RTE_MAX_ETHPORTS);
	memset(txring_numa, NUMA_NO_CONFIG, RTE_MAX_ETHPORTS);
    return 0;
}

static int get_eth_overhead(struct rte_eth_dev_info *dev_info)
{
	uint32_t eth_overhead;

	if (dev_info->max_mtu != UINT16_MAX &&
	    dev_info->max_rx_pktlen > dev_info->max_mtu)
		eth_overhead = dev_info->max_rx_pktlen - dev_info->max_mtu;
	else
		eth_overhead = RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;

	return eth_overhead;
}

static int eth_macaddr_get_print_err(uint16_t port_id, struct rte_ether_addr *mac_addr)
{
	int ret;

	ret = rte_eth_macaddr_get(port_id, mac_addr);
	if (ret != 0)
		fprintf(stderr,
			"Error getting device (port %u) mac address: %s\n",
			port_id, rte_strerror(-ret));

	return ret;
}

static int init_config_port_offloads(portid_t pid, uint32_t socket_id)
{
    struct rte_port *port = &ports[pid];
    int ret;
    int i;

    port->dev_conf.txmod = port_config[pid].tx_mode;
    port->dev_conf.rxmod = port_config[pid].rx_mode;

    ret = eth_dev_info_get_print_err(pid, &port->dev_info);
    if (ret != 0) {
        TRACENET_LOG(ERR, "rte_eth_dev_info_get() failed\n");
        return ret;
    }

    if (!(port->dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE))
		port->dev_conf.txmode.offloads &=
			~RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
        
    /* Apply Rx offloads configuration */
    for (i = 0; i < port->dev_info.max_rx_queues; i++)
		port->rxq[i].conf.offloads = port->dev_conf.rxmode.offloads;
    /* Apply Tx offloads configuration */
	for (i = 0; i < port->dev_info.max_tx_queues; i++)
		port->txq[i].conf.offloads = port->dev_conf.txmode.offloads;
    
    if (port_config[pid].eth_link_speed)
		port->dev_conf.link_speeds = port_config[pid].eth_link_speed;
    
    if (port_config[pid].max_rx_pkt_len)
		port->dev_conf.rxmode.mtu = port_config[pid].max_rx_pkt_len -
			get_eth_overhead(&port->dev_info);

    /* set flag to initialize port/queue */
    port->need_reconfig = 1;
	port->need_reconfig_queues = 1;
	port->socket_id = socket_id;
	port->tx_metadata = 0;

    /*
	 * Check for maximum number of segments per MTU.
	 * Accordingly update the mbuf data size.
	 */
    if (port->dev_info.rx_desc_lim.nb_mtu_seg_max != UINT16_MAX &&
	    port->dev_info.rx_desc_lim.nb_mtu_seg_max != 0) {
		uint32_t eth_overhead = get_eth_overhead(&port->dev_info);
		uint16_t mtu;

		if (rte_eth_dev_get_mtu(pid, &mtu) == 0) {
			uint16_t data_size = (mtu + eth_overhead) /
				port->dev_info.rx_desc_lim.nb_mtu_seg_max;
			uint16_t buffer_size = data_size + RTE_PKTMBUF_HEADROOM;

			if (buffer_size > port_config[pid].mbuf_data_size[0]) {
				port_config[pid].mbuf_data_size[0] = buffer_size;
				RT_ETHDEV_LOG(WARNING,
					"Configured mbuf size of the first segment %lu on port %d\n",
					port_config[pid].mbuf_data_size[0], pid);
			}
		}
	}

    return 0;
}

static void rxtx_port_config(portid_t pid)
{
    uint16_t qid;
    uint64_t offloads;
    struct rte_port *port = &ports[pid];

    for (qid = 0; qid < port_config[pid].nb_rxq; qid++) {
        offloads = port->rxq[qid].conf.offloads;
		port->rxq[qid].conf = port->dev_info.default_rxconf;

		//doto set rxq share
        if (rxq_share > 0 &&
		    (port->dev_info.dev_capa & RTE_ETH_DEV_CAPA_RXQ_SHARE)) {
			/* Non-zero share group to enable RxQ share. */
			port->rxq[qid].conf.share_group = pid / rxq_share + 1;
			port->rxq[qid].conf.share_qid = qid; /* Equal mapping. */
		}

        if (offloads != 0)
			port->rxq[qid].conf.offloads = offloads;

        /* Check if any Rx parameters have been passed */
		if (port_config[pid].rx_pthresh != RTE_PMD_PARAM_UNSET)
			port->rxq[qid].conf.rx_thresh.pthresh = port_config[pid].rx_pthresh;

		if (port_config[pid].rx_hthresh != RTE_PMD_PARAM_UNSET)
			port->rxq[qid].conf.rx_thresh.hthresh = port_config[pid].rx_hthresh;

		if (port_config[pid].rx_wthresh != RTE_PMD_PARAM_UNSET)
			port->rxq[qid].conf.rx_thresh.wthresh = port_config[pid].rx_wthresh;

		if (port_config[pid].rx_free_thresh != RTE_PMD_PARAM_UNSET)
			port->rxq[qid].conf.rx_free_thresh = port_config[pid].rx_free_thresh;

		if (port_config[pid].rx_drop_en != RTE_PMD_PARAM_UNSET)
			port->rxq[qid].conf.rx_drop_en = port_config[pid].rx_drop_en;

		port->nb_rx_desc[qid] = port_config[pid].nb_rxd;
    }

    for (qid = 0; qid < port_config[pid].nb_txq; qid++) {
        offloads = port->txq[qid].conf.offloads;
		port->txq[qid].conf = port->dev_info.default_txconf;
		if (offloads != 0)
			port->txq[qid].conf.offloads = offloads;

		/* Check if any Tx parameters have been passed */
		if (port_config[pid].tx_pthresh != RTE_PMD_PARAM_UNSET)
			port->txq[qid].conf.tx_thresh.pthresh = port_config[pid].tx_pthresh;

		if (port_config[pid].tx_hthresh != RTE_PMD_PARAM_UNSET)
			port->txq[qid].conf.tx_thresh.hthresh = port_config[pid].tx_hthresh;

		if (port_config[pid].tx_wthresh != RTE_PMD_PARAM_UNSET)
			port->txq[qid].conf.tx_thresh.wthresh = port_config[pid].tx_wthresh;

		if (port_config[pid].tx_rs_thresh != RTE_PMD_PARAM_UNSET)
			port->txq[qid].conf.tx_rs_thresh = port_config[pid].tx_rs_thresh;

		if (port_config[pid].tx_free_thresh != RTE_PMD_PARAM_UNSET)
			port->txq[qid].conf.tx_free_thresh = port_config[pid].tx_free_thresh;

		port->nb_tx_desc[qid] = port_config[pid].nb_txd; 
    }
}

static int init_port_config_(portid_t pid)
{
	struct rte_port *port;
	port = &ports[pid];
	int ret = 0;

	ret = eth_dev_info_get_print_err(pid, &port->dev_info);
	if (ret != 0)
		return ret;

	if (port_config[pid].nb_rxq > 1) {
		port->dev_conf.rx_adv_conf.rss_conf.rss_key = NULL;
			port->dev_conf.rx_adv_conf.rss_conf.rss_hf =
				port_config[pid].rss_hf & port->dev_info.flow_type_rss_offloads;
	} else {
		port->dev_conf.rx_adv_conf.rss_conf.rss_key = NULL;
		port->dev_conf.rx_adv_conf.rss_conf.rss_hf = 0;
	}

	if (port->dev_conf.rx_adv_conf.rss_conf.rss_hf != 0) {
		port->dev_conf.rxmode.mq_mode =
			(enum rte_eth_rx_mq_mode)
				(port_config[pid].rx_mq_mode & RTE_ETH_MQ_RX_RSS);
	} else {
		port->dev_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
		port->dev_conf.rxmode.offloads &=
				~RTE_ETH_RX_OFFLOAD_RSS_HASH;

		for (i = 0;
				i < port->dev_info.nb_rx_queues;
				i++)
			port->rxq[i].conf.offloads &=
				~RTE_ETH_RX_OFFLOAD_RSS_HASH;
	}

	if (port_config[pid].specialize_init)
		port_config[pid].specialize_init(&port->dev_conf);
}

int rt_init_port_config(portid_t pid)
{
	portid_t pi;
	uint32_t socket_id;
	int ret = 0;

	RTE_ETH_FOREACH_DEV(pi) {
		if (pid != pi)
			continue;
		
		uint32_t socket_id;

#if NUMA_SUPPORT
			socket_id = port_config[pid].port_numa;
			if (port_numa[pid] == NUMA_NO_CONFIG) {
				socket_id = rte_eth_dev_socket_id(pid);

                /*
				 * if socket_id is invalid,
				 * set to the 0.
				 */
				if (check_socket_id(socket_id) < 0)
					socket_id = 0;
            }
#else
			socket_id = 0;
#endif // NUMA_SUPPORT
		/* Apply default TxRx configuration for all ports */
		ret = init_config_port_offloads(pid, socket_id);
        if (ret < 0)
            return -1;
		
		ret = init_port_config_(pi);
		if (ret < 0)
			return -1;

		rxtx_port_config(pid);

		ret = eth_macaddr_get_print_err(pid, &port->eth_addr);
		if (ret != 0)
			return -1;
		
		if (port_config[pid].lsc_interrupt && (*port->dev_info.dev_flags & RTE_ETH_DEV_INTR_LSC))
			port->dev_conf.intr_conf.lsc = 1;
		if (port_config[pid].rmv_interrupt && (*port->dev_info.dev_flags & RTE_ETH_DEV_INTR_RMV))
			port->dev_conf.intr_conf.rmv = 1;
	}

	return 0;
}

static int eth_dev_configure_mp(uint16_t port_id, uint16_t nb_rx_q, uint16_t nb_tx_q,
		      const struct rte_eth_conf *dev_conf)
{
	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		return rte_eth_dev_configure(port_id, nb_rx_q, nb_tx_q,
					dev_conf);
	return 0;
}

void add_rx_dump_callbacks(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	for (queue = 0; queue < dev_info.nb_rx_queues; queue++)
		if (!ports[portid].rx_dump_cb[queue])
			ports[portid].rx_dump_cb[queue] =
				rte_eth_add_rx_callback(portid, queue,
					dump_rx_pkts, NULL);
}

void add_tx_dump_callbacks(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	for (queue = 0; queue < dev_info.nb_tx_queues; queue++)
		if (!ports[portid].tx_dump_cb[queue])
			ports[portid].tx_dump_cb[queue] =
				rte_eth_add_tx_callback(portid, queue,
							dump_tx_pkts, NULL);
}

void remove_rx_dump_callbacks(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	for (queue = 0; queue < dev_info.nb_rx_queues; queue++)
		if (ports[portid].rx_dump_cb[queue]) {
			rte_eth_remove_rx_callback(portid, queue,
				ports[portid].rx_dump_cb[queue]);
			ports[portid].rx_dump_cb[queue] = NULL;
		}
}

void remove_tx_dump_callbacks(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	for (queue = 0; queue < dev_info.nb_tx_queues; queue++)
		if (ports[portid].tx_dump_cb[queue]) {
			rte_eth_remove_tx_callback(portid, queue,
				ports[portid].tx_dump_cb[queue]);
			ports[portid].tx_dump_cb[queue] = NULL;
		}
}

void configure_rxtx_dump_callbacks(uint16_t verbose)
{
	portid_t portid;

	RTE_ETH_FOREACH_DEV(portid)
	{
		if (verbose == 1 || verbose > 2)
			add_rx_dump_callbacks(portid);
		else
			remove_rx_dump_callbacks(portid);
		if (verbose >= 2)
			add_tx_dump_callbacks(portid);
		else
			remove_tx_dump_callbacks(portid);
	}
}

static int eth_dev_start_mp(uint16_t port_id)
{
	int ret;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY;) {
		ret = rte_eth_dev_start(port_id);
		if (ret != 0)
			return ret;
	}
	
	return 0;
}

/** Fill helper structures for specified port to show extended statistics. */
static void fill_xstats_display_info_for_port(portid_t pi)
{
	unsigned int stat, stat_supp;
	const char *xstat_name;
	struct rte_port *port;
	uint64_t *ids_supp;
	int rc;

	if (xstats_display_num == 0)
		return;

	if (pi == (portid_t)RTE_PORT_ALL) {
		fill_xstats_display_info();
		return;
	}

	port = &ports[pi];
	if (port->port_status != RTE_PORT_STARTED)
		return;

	if (!port->xstats_info.allocated && alloc_xstats_display_info(pi) != 0)
		rte_exit(EXIT_FAILURE,
			 "Failed to allocate xstats display memory\n");
	
	ids_supp = port->xstats_info.ids_supp;
	for (stat = stat_supp = 0; stat < xstats_display_num; stat++) {
		xstat_name = xstats_display[stat].name;
		rc = rte_eth_xstats_get_id_by_name(pi, xstat_name,
						   ids_supp + stat_supp);
		if (rc != 0) {
			fprintf(stderr, "No xstat '%s' on port %u - skip it %u\n",
				xstat_name, pi, stat);
			continue;
		}
		stat_supp++;
	}

	port->xstats_info.ids_supp_sz = stat_supp;
}
