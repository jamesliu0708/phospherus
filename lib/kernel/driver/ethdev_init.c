#include <driver/rt_ethdev.h>
#include <errno.h>
#include <stdio.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_alarm.h>
#include <rte_cycles.h>
#include <rte_mempool.h>
#include <rte_cfgfile.h>
#include <rte_lcore.h>
#include <driver/rt_ethdev_config.h>
#include <driver/rt_ethdev_core.h>
#include "driver/eth_common.h"

static struct rte_mempool *mempools[RTE_MAX_LCORE * MAX_SEGS_BUFFER_SPLIT];
static uint16_t mbuf_data_size[MAX_SEGS_BUFFER_SPLIT] = {
	DEFAULT_MBUF_DATA_SIZE
}; /**< Mbuf data space size. */

struct ethdev_config ethdev_config = {
	.logtype = -1,
	.level = RTE_LOG_INFO,
	.total_num_mbufs = 0,
	.mp_alloc_type = MP_ALLOC_NATIVE,
	.mp_create_type = MP_PER_SOCKET,
};

int rt_port_load_cfg(const char *profile) 
{
	int ret = 0;
	if (profile == NULL)
		return 0;
	struct rte_cfgfile *file = rte_cfgfile_load(profile, 0);
	if (file == NULL) 
		return -1;
	
	ret = cfg_load_port(file);
	if (ret)
		goto _app_load_cfg_profile_error_return;
	
	ret = cfg_load_subport(file);
	if (ret)
		goto _app_load_cfg_profile_error_return;
	
_app_load_cfg_profile_error_return:
	rte_cfgfile_close(file);

	return ret;
}

int rt_eth_log_setup(const char* logname, uint32_t level)
{
	int ret = -1;
	ethdev_config.logtype = rte_log_register(logname);
	if (ethdev_config.logtype < 0)
		return ethdev_config.logtype;
	ret = rte_log_set_level(ethdev_config.logtype, level);
	return ret == 0? ethdev_config.logtype: -1;
}

static int eth_dev_stop_mp(uint16_t port_id)
{
	int ret;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ret = rte_eth_dev_stop(port_id);
		if (ret != 0)
			return ret;
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

	RT_ETHDEV_LOG(INFO, "Checking link statuses...\n");
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
					RT_ETHDEV_LOG(WARNING,
						"Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status,
					sizeof(link_status), &link);
				RT_ETHDEV_LOG(INFO,
					"Port %d %s\n", portid, link_status);
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

void rt_port_stop(portid_t pid)
{
	portid_t pi;
	struct rte_port *ports = NULL;
	struct rte_port *port;
	struct port_config *ports_cfg = port_get_config();
	int need_check_link_status = 0;
	int ret;

	if (port_id_is_invalid(pid))
		return;

	RT_ETHDEV_LOG(INFO, "Stopping ports...\n");

	ports = rt_eth_get_port();
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
			RT_ETHDEV_LOG(ERR, "Port %d can not be set into stopped\n",
				pi);
		need_check_link_status = 1;
	}
	if (need_check_link_status && !ports_cfg[pid].no_link_check)
		check_all_ports_link_status(RTE_PORT_ALL);
}

static void free_xstats_display_info(portid_t pi)
{
	struct rte_port* port = NULL;
	
	if (pi > RTE_MAX_ETHPORTS)
		return;
	port = &rt_eth_get_port()[pi];
	if (!port->xstats_info.allocated)
		return;
	free(port->xstats_info.ids_supp);
	free(port->xstats_info.prev_values);
	free(port->xstats_info.curr_values);
	port->xstats_info.allocated = false;
}

void rt_port_close(portid_t pid)
{
	portid_t pi;
	struct port_config* port_config = NULL;
	struct rte_port *ports = NULL;
	struct rte_port *port = NULL;

	if (port_id_is_invalid(pid))
		return;
	
	RT_ETHDEV_LOG(INFO, "Closing ports...\n");

	ports = rt_eth_get_port();
	RTE_ETH_FOREACH_DEV(pi) {
		if (pid != pi && pid != (portid_t)RTE_PORT_ALL)
			continue;

		port = &ports[pi];
		if (port->port_status == RTE_PORT_CLOSED) {
			RT_ETHDEV_LOG(INFO, "Port %d is already closed\n", pi);
			continue;
		}

		if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
			rte_eth_dev_close(pi);
		}

		free_xstats_display_info(pi);

		port->port_status == RTE_PORT_CLOSED;
		port_config = port_get_config();
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
	struct port_config *ports_cfg = NULL;
	int need_to_start = 0;
	portid_t port_id = (intptr_t)arg;
	int org_no_link_check = 0;
	struct rte_eth_dev_info dev_info;
	int ret;

	ports_cfg = port_get_config();
	org_no_link_check = ports_cfg[port_id].no_link_check;

	RTE_ETH_VALID_PORTID_OR_RET(port_id);

	ports_cfg[port_id].no_link_check = 1;
	rt_port_stop(port_id);
	ports_cfg[port_id].no_link_check = org_no_link_check;

	ret = eth_dev_info_get_print_err(port_id, &dev_info);
	if (ret != 0)
		RT_ETHDEV_LOG(ERR,
			"Failed to get device info for port %d, not detaching\n",
			port_id);
	else {
		struct rte_device *device = dev_info.device;
		rt_port_close(port_id);
		detach_device(device); /* might be already removed or have more ports */
	}
}

/* This function is used by the interrupt thread */
static int eth_event_callback(portid_t port_id, enum rte_eth_event_type type, void *param,
		  void *ret_param)
{
    RTE_SET_USED(param);
	RTE_SET_USED(ret_param);
	struct port_config* ports_cfg = NULL;
	struct rte_port *ports = NULL;

    if (type >= RTE_ETH_EVENT_MAX) {
		RT_ETHDEV_LOG(ERR,
			"Port %" PRIu16 ": %s called upon invalid event %d\n",
			port_id, __func__, type);
	} else {
		RT_ETHDEV_LOG(ERR,
			"Port %" PRIu16 ": %d event\n", port_id,
			type);
	}

	ports_cfg = port_get_config();
	ports = rt_eth_get_port();
    switch (type) {
	case RTE_ETH_EVENT_NEW:
		if (ports_cfg[port_id].probed == 0)
			ports_cfg[port_id].probed == 1;
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
		RT_ETHDEV_LOG(INFO, "Port %u is closed\n", port_id);
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
			RT_ETHDEV_LOG(INFO, "Received avail_thresh event, port: %u, rxq_id: %u\n",
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
        ret = rte_eth_dev_callback_register(RTE_ETH_ALL, 
                event,
                eth_event_callback,
                NULL);
        if (ret != 0) {
            RT_ETHDEV_LOG(ERR, "Failed to register callback for "
                    "%d event\n", event);
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
static struct rte_mempool * mbuf_pool_create(const char* pool_name, const char* alloc_op_name, uint16_t mbuf_seg_size, unsigned nb_mbuf,
		 unsigned int socket_id, uint16_t size_idx)
{
	struct rte_mempool *rte_mp = NULL;
	int ret = 0;
	struct ethdev_config* ethdev_cfg = NULL;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		rte_mp = rte_mempool_lookup(pool_name);
		if (rte_mp == NULL)
			RT_ETHDEV_LOG(ERR, 
				"Get mbuf pool for socket %u failed: %s\n",
				socket_id, rte_strerror(rte_errno));
		return rte_mp;
	}

	RT_ETHDEV_LOG(INFO, 
		"create a new mbuf pool <%s>: n=%u, size=%u, socket=%u\n",
		pool_name, nb_mbuf, mbuf_seg_size, socket_id);
	
	ethdev_cfg = ethdev_get_config();
	switch (ethdev_cfg->mp_alloc_type) {
	case MP_ALLOC_NATIVE:
		{
			rte_mp = rte_pktmbuf_pool_create_by_ops(pool_name, nb_mbuf, 
							(unsigned int) ethdev_cfg->mb_mempool_cache, 0, mbuf_seg_size, socket_id, alloc_op_name);
			break;
		}
	case MP_ALLOC_ANON:
		{
			rte_mp = rte_mempool_create_empty(pool_name, nb_mbuf,
				mbuf_seg_size, (unsigned int) ethdev_cfg->mb_mempool_cache,
				sizeof(struct rte_pktmbuf_pool_private),
				socket_id, (unsigned int) ethdev_cfg->mempool_flag);
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
			bool huge = ethdev_cfg->mp_alloc_type == MP_ALLOC_XMEM_HUGE;

			if (setup_extmem(nb_mbuf, mbuf_seg_size, huge) < 0)
				rte_exit(EXIT_FAILURE, "Could not create external memory\n");

			heap_socket =
				rte_malloc_heap_get_socket(EXTMEM_HEAP_NAME);
			if (heap_socket < 0)
				rte_exit(EXIT_FAILURE, "Could not get external memory socket ID\n");

			rte_mp = rte_pktmbuf_pool_create_by_ops(pool_name, nb_mbuf,
					(unsigned int) ethdev_cfg->mb_mempool_cache, 0, mbuf_seg_size,
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

			RT_ETHDEV_LOG(INFO, "preferred mempool ops selected: %s\n",
					rte_mbuf_best_mempool_ops());
			rte_mp = rte_pktmbuf_pool_create_extbuf
					(pool_name, nb_mbuf, (unsigned int) ethdev_cfg->mb_mempool_cache,
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

static void mbuf_pool_setup()
{
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	unsigned int nb_mbuf_per_pool;
	struct ethdev_config *ethdev_cfg = NULL;
	unsigned int socket_id;

	/*
	 * Create pools of mbuf.
	 * If NUMA support is disabled, create a single pool of mbuf in
	 * socket 0 memory by default.
	 * Otherwise, create a pool of mbuf in the memory of sockets 0 and 1.
	 *
	 * Use the maximum value of nb_rxd and nb_txd here, then nb_rxd and
	 * nb_txd can be configured at run time.
	 */
	ethdev_cfg = ethdev_get_config();
	if (ethdev_cfg->total_num_mbufs)
		nb_mbuf_per_pool = ethdev_cfg->total_num_mbufs;
	else {
		if (ethdev_cfg->mp_create_type == MP_PER_SOCKET || ethdev_cfg->mp_create_type == MP_PER_QUEUE) {
			nb_mbuf_per_pool = RX_DESC_MAX +
				TX_DESC_MAX + MAX_PKT_BURST;
		} else {
			nb_mbuf_per_pool = RX_DESC_MAX +
				(rte_lcore_count() * ethdev_cfg->mb_mempool_cache) +
				TX_DESC_MAX + MAX_PKT_BURST;
			nb_mbuf_per_pool *= ethdev_cfg->nb_cfg_ports;
		}
	}
	
	if (ethdev_cfg->mp_create_type == MP_PER_SOCKET) {
#if NUMA_SUPPORT
		uint8_t i, j;
		for (i = 0; i < ethdev_cfg->num_sockets; i++)
			for (socket_id = 0; socket_id < RTE_MAX_NUMA_NODES; ++socket_id) {
				if (ethdev_cfg->socket_ids[socket_id] == 0) 
					continue;
				for (j = 0; j < ethdev_cfg->mbuf_data_size_n; j++) {
					memset(pool_name, 0, RTE_MEMPOOL_NAMESIZE);
					mbuf_poolname_build(socket_id, pool_name, sizeof(pool_name), j);
					mempools[i * MAX_SEGS_BUFFER_SPLIT + j] = 
									mbuf_pool_create(
												pool_name, NULL, 
												ethdev_cfg->mbuf_data_size[j], nb_mbuf_per_pool,
												socket_id, j);
				}
			}
#else
		uint8_t i;
		memset(pool_name, 0, RTE_MEMPOOL_NAMESIZE);
		mbuf_poolname_build(0, pool_name, sizeof(pool_name), j);
		for (i = 0; i < ethdev_cfg->mbuf_data_size_n; i++)
			mempools[i] = mbuf_pool_create
							(poolname, ethdev_cfg->mbuf_data_size[i],
							nb_mbuf_per_pool,
							0, i);
#endif // NUMA_SUPPORT
	} else {
		uint8_t i, j;
		unsigned int socketid;
		for (i = 0; i < ethdev_cfg->num_cpuids; i++) {
			for (j = 0; j < ethdev_cfg->mbuf_data_size_n; j++) {
				memset(pool_name, 0, RTE_MEMPOOL_NAMESIZE);
				mbuf_poolname_build(ethdev_cfg->cpu_ids[i], pool_name, sizeof(pool_name), j);
				socketid = eal_cpu_socket_id(ethdev_cfg->cpu_ids[i]);
				const char* mp_alloc_op = NULL;
				if (ethdev_cfg->mp_create_type == MP_PER_QUEUE)
					mp_alloc_op = "ring_sp_sc";
				mempools[i * MAX_SEGS_BUFFER_SPLIT + j] =
					mbuf_pool_create(
							  pool_name, mp_alloc_op, 
							  ethdev_cfg->mbuf_data_size[j], nb_mbuf_per_pool,
							  socketid, j);
			}
		}
	}
}

static int eth_dev_start_mp(portid_t port_id)
{
	int ret;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ret = rte_eth_dev_start(port_id);
		if (ret != 0)
			return ret;
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

static inline struct rte_mempool *mbuf_pool_find(unsigned int tag_id, uint16_t idx)
{
	char pool_name[RTE_MEMPOOL_NAMESIZE];

	mbuf_poolname_build(tag_id, pool_name, sizeof(pool_name), idx);
	return rte_mempool_lookup((const char *)pool_name);
}

/** Fill helper structures for specified port to show extended statistics. */
static void fill_xstats_display_info_for_port(portid_t pi)
{
	// unsigned int stat, stat_supp;
	// const char *xstat_name;
	// struct rte_port *port;
	// uint64_t *ids_supp;
	// int rc;

	// if (xstats_display_num == 0)
	// 	return;

	// if (pi == (portid_t)RTE_PORT_ALL) {
	// 	fill_xstats_display_info();
	// 	return;
	// }

	// port = &ports[pi];
	// if (port->port_status != RTE_PORT_STARTED)
	// 	return;

	// if (!port->xstats_info.allocated && alloc_xstats_display_info(pi) != 0)
	// 	rte_exit(EXIT_FAILURE,
	// 		 "Failed to allocate xstats display memory\n");
	
	// ids_supp = port->xstats_info.ids_supp;
	// for (stat = stat_supp = 0; stat < xstats_display_num; stat++) {
	// 	xstat_name = xstats_display[stat].name;
	// 	rc = rte_eth_xstats_get_id_by_name(pi, xstat_name,
	// 					   ids_supp + stat_supp);
	// 	if (rc != 0) {
	// 		fprintf(stderr, "No xstat '%s' on port %u - skip it %u\n",
	// 			xstat_name, pi, stat);
	// 		continue;
	// 	}
	// 	stat_supp++;
	// }

	// port->xstats_info.ids_supp_sz = stat_supp;
}

int rt_port_start(portid_t pid)
{
	int need_check_link_status = -1;
	portid_t pi = 0;
	struct rte_port *ports;
	int diag = 0;
	queueid_t qi = 0;
	struct port_config *ports_cfg = port_get_config();
	ports = rt_eth_get_port();

	if (port_id_is_invalid(pid))
		return 0;
	
	RTE_ETH_FOREACH_DEV(pi) {
		struct port_config *port_cfg = &ports_cfg[pi];
		struct rte_port *port = &ports[pi];
		if (pid != pi && pid != (portid_t)RTE_PORT_ALL)
			continue;

		need_check_link_status = 0;
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
			diag = eth_dev_configure_mp(pi, port_cfg->nb_rxq, port_cfg->nb_txq,
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
			for (qi = 0; qi < port_cfg->nb_txq; qi++) {
				struct rte_eth_txconf *conf =
							&port->txq[qi].conf;
#if NUMA_SUPPORT
				if (port_cfg->txring_numa != NUMA_NO_CONFIG)
					diag = rte_eth_tx_queue_setup(pi, qi,
						port->nb_tx_desc[qi],
						port_cfg->txring_numa,
						&(port->txq[qi].conf));
				else
#endif // NUMA_SUPPORT
				diag = rte_eth_tx_queue_setup(pi, qi,
					port->nb_tx_desc[qi],
					0, &(port->txq[qi].conf));
				
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
			for (qi = 0; qi < port_cfg->nb_rxq; qi++) {
				struct rte_mempool *mp = NULL;
				/* setup rx queues */
				tag_id = port_cfg->rxring_numa;

				if (ethdev_config.mp_alloc_type == MP_PER_SOCKET) {
#if NUMA_SUPPORT
					if (port_cfg->rxring_numa != NUMA_NO_CONFIG)
						tag_id = port_cfg->rxring_numa;
					else
#else
						tag_id = 0;
#endif // NUMA_SUPPORT
					mp = mbuf_pool_find(tag_id, 0);
					if (mp == NULL) {
						RT_ETHDEV_LOG(ERR,
							"Failed to setup RX queue: No mempool allocation on the socket %d\n",
							port_cfg->rxring_numa);
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
		// todo
		// if (clear_ptypes) {
		// 	diag = rte_eth_dev_set_ptypes(pi, RTE_PTYPE_UNKNOWN,
		// 			NULL, 0);
		// 	if (diag < 0)
		// 		RT_ETHDEV_LOG(ERR,
		// 			"Port %d: Failed to disable Ptype parsing\n",
		// 			pi);
		// }

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
	
	if (need_check_link_status == 1 && !ports_cfg->no_link_check)
		check_all_ports_link_status(RTE_PORT_ALL);
	else if (need_check_link_status == 0)
		RT_ETHDEV_LOG(ERR, "Please stop the ports first\n");

	fill_xstats_display_info_for_port(pid);
}

int rt_ethdev_setup(const char* cfgfile)
{
	int ret = 0;
	uint16_t probed_ports_cnt = 0;
	uint16_t cfg_ports_cnt = 0;
	portid_t port_id;
	struct port_config *ports_cfg = NULL;
	struct ethdev_config *ethdev_cfg = NULL;

	rt_port_reset_config();
	ret = rt_port_load_cfg(cfgfile);
	if (ret < 0) {
		fprintf(stderr, "rt_ethdev: Cannot load cfgfile\n");
		return ret;
	}

	ethdev_cfg = ethdev_get_config();
	ret = rt_eth_log_setup("rt_ethdev", ethdev_cfg->level);
	if (ret < 0) {
		fprintf(stderr, "rt_ethdev: Cannot register log type\n");
		return ret;
	}

	ret = register_eth_event_callback();
	if (ret != 0) {
		RT_ETHDEV_LOG(ERR, "Cannot register for ethdev events\n");
		return ret;
	}

	ports_cfg = port_get_config();
	RTE_ETH_FOREACH_DEV(port_id) {
		ports_cfg[port_id].probed = 1;
		probed_ports_cnt++;
		if (ports_cfg[port_id].selected)
			cfg_ports_cnt++;
	}
	ethdev_cfg->nb_ports = probed_ports_cnt;

	if (ethdev_cfg->nb_ports == 0)
		RT_ETHDEV_LOG(WARNING, "No probed ethernet devices\n");
	if (ethdev_cfg->nb_cfg_ports == 0)
		RT_ETHDEV_LOG(WARNING, "No selected ethernet devices\n");

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; ++port_id)
	{
		if (!ports_cfg[port_id].selected)
			continue;
		if (ports_cfg[port_id].selected && !ports_cfg[port_id].probed) {
			RT_ETHDEV_LOG(WARNING, 
				"Port id %d is selected but not probed\n", port_id);
			continue;
		}
		
		if (!ports_cfg[port_id].nb_rxq && !ports_cfg[port_id].nb_txq)
			RT_ETHDEV_LOG(WARNING,
				"Warning: Either rx or tx queues should be non-zero\n");
		
		if (ports_cfg[port_id].nb_rxq > 1 
				&& ports_cfg[port_id].nb_rxq > ports_cfg[port_id].nb_txq)
			RT_ETHDEV_LOG(WARNING,
				"Warning: nb_rxq=%d enables RSS configuration, but nb_txq=%d will prevent to fully test it.\n",
				ports_cfg[port_id].nb_rxq, ports_cfg[port_id].nb_txq);

		ret = rt_port_setup_config(port_id);
		if (ret != 0) {
			RT_ETHDEV_LOG(WARNING, 
				"Port id %d init failed\n", port_id);
			ports_cfg[port_id].selected = 0;
			continue;
		}
	}

	mbuf_pool_setup();

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; ++port_id)
	{
		if (!ports_cfg[port_id].selected || !ports_cfg[port_id].probed)
			continue;

		ret = rt_port_start(port_id);
		if (ret != 0)
			continue;

		if (ports_cfg[port_id].promiscuous_enable) {
			ret = rte_eth_promiscuous_enable(port_id);
			if (ret != 0)
			RT_ETHDEV_LOG(WARNING,
				"Error during enabling promiscuous mode for port %u: %s - ignore\n",
				port_id, rte_strerror(-ret));
		}
	}

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

static int config_port_setup_offloads(portid_t pid, uint32_t socket_id)
{
	struct rte_port *ports = rt_eth_get_port();
    struct rte_port *port = &ports[pid];
	struct port_config  *ports_cfg = port_get_config();
	struct ethdev_config *ethdev_cfg = ethdev_get_config();
    int ret;
    unsigned int i;

    port->dev_conf.txmode = ports_cfg[pid].tx_mode;
    port->dev_conf.rxmode = ports_cfg[pid].rx_mode;

    ret = eth_dev_info_get_print_err(pid, &port->dev_info);
    if (ret != 0) {
        RT_ETHDEV_LOG(ERR, "rte_eth_dev_info_get() failed\n");
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
    
    if (ports_cfg[pid].eth_link_speed)
		port->dev_conf.link_speeds = ports_cfg[pid].eth_link_speed;
    
    if (ports_cfg[pid].max_rx_pkt_len)
		port->dev_conf.rxmode.mtu = ports_cfg[pid].max_rx_pkt_len -
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

			if (buffer_size > ethdev_cfg->mbuf_data_size[0]) {
				ethdev_cfg->mbuf_data_size[0] = buffer_size;
				RT_ETHDEV_LOG(WARNING,
					"Configured mbuf size of the first segment %lu on port %d\n",
					ethdev_cfg->mbuf_data_size[0], pid);
			}
		}
	}

	for (i = 0; i < RTE_MAX_QUEUES_PER_PORT; ++i) {
		port->nb_rx_desc[i] = ports_cfg[pid].nb_rx_desc[i];
		port->nb_tx_desc[i] = ports_cfg[pid].nb_tx_desc[i];
	}

    return 0;
}

static void rxtx_port_config(portid_t pid)
{
	struct rte_port *ports = rt_eth_get_port();
    uint16_t qid;
    uint64_t offloads;
	struct port_config *port_cfg = port_get_config();
    struct rte_port *port = &ports[pid];

    for (qid = 0; qid < port_cfg[pid].nb_rxq; qid++) {
        offloads = port->rxq[qid].conf.offloads;
		port->rxq[qid].conf = port->dev_info.default_rxconf;

		//doto set rxq share
        // if (rxq_share > 0 &&
		//     (port->dev_info.dev_capa & RTE_ETH_DEV_CAPA_RXQ_SHARE)) {
		// 	/* Non-zero share group to enable RxQ share. */
		// 	port->rxq[qid].conf.share_group = pid / rxq_share + 1;
		// 	port->rxq[qid].conf.share_qid = qid; /* Equal mapping. */
		// }

        if (offloads != 0)
			port->rxq[qid].conf.offloads = offloads;

        /* Check if any Rx parameters have been passed */
		if (port_cfg[pid].rx_pthresh != RTE_PARAM_UNSET)
			port->rxq[qid].conf.rx_thresh.pthresh = port_cfg[pid].rx_pthresh;

		if (port_cfg[pid].rx_hthresh != RTE_PARAM_UNSET)
			port->rxq[qid].conf.rx_thresh.hthresh = port_cfg[pid].rx_hthresh;

		if (port_cfg[pid].rx_wthresh != RTE_PARAM_UNSET)
			port->rxq[qid].conf.rx_thresh.wthresh = port_cfg[pid].rx_wthresh;

		if (port_cfg[pid].rx_free_thresh != RTE_PARAM_UNSET)
			port->rxq[qid].conf.rx_free_thresh = port_cfg[pid].rx_free_thresh;

		if (port_cfg[pid].rx_drop_en != RTE_PARAM_UNSET)
			port->rxq[qid].conf.rx_drop_en = port_cfg[pid].rx_drop_en;

		port->nb_rx_desc[qid] = port_cfg[pid].nb_rxd;
    }

    for (qid = 0; qid < port_cfg[pid].nb_txq; qid++) {
        offloads = port->txq[qid].conf.offloads;
		port->txq[qid].conf = port->dev_info.default_txconf;
		if (offloads != 0)
			port->txq[qid].conf.offloads = offloads;

		/* Check if any Tx parameters have been passed */
		if (port_cfg[pid].tx_pthresh != RTE_PARAM_UNSET)
			port->txq[qid].conf.tx_thresh.pthresh = port_cfg[pid].tx_pthresh;

		if (port_cfg[pid].tx_hthresh != RTE_PARAM_UNSET)
			port->txq[qid].conf.tx_thresh.hthresh = port_cfg[pid].tx_hthresh;

		if (port_cfg[pid].tx_wthresh != RTE_PARAM_UNSET)
			port->txq[qid].conf.tx_thresh.wthresh = port_cfg[pid].tx_wthresh;

		if (port_cfg[pid].tx_rs_thresh != RTE_PARAM_UNSET)
			port->txq[qid].conf.tx_rs_thresh = port_cfg[pid].tx_rs_thresh;

		if (port_cfg[pid].tx_free_thresh != RTE_PARAM_UNSET)
			port->txq[qid].conf.tx_free_thresh = port_cfg[pid].tx_free_thresh;

		port->nb_tx_desc[qid] = port_cfg[pid].nb_txd; 
    }
}

static int port_setup_ex_config(portid_t pid)
{
	struct rte_port *ports = rt_eth_get_port();
	struct rte_port *port = NULL;
	struct port_config *port_cfg = NULL;
	int ret = 0;
	int i = 0;

	port_cfg = port_get_config();
	port = &ports[pid];

	ret = eth_dev_info_get_print_err(pid, &port->dev_info);
	if (ret != 0)
		return ret;

	if (port_cfg[pid].nb_rxq > 1) {
		port->dev_conf.rx_adv_conf.rss_conf.rss_key = NULL;
			port->dev_conf.rx_adv_conf.rss_conf.rss_hf =
				port_cfg[pid].rss_hf & port->dev_info.flow_type_rss_offloads;
	} else {
		port->dev_conf.rx_adv_conf.rss_conf.rss_key = NULL;
		port->dev_conf.rx_adv_conf.rss_conf.rss_hf = 0;
	}

	if (port->dev_conf.rx_adv_conf.rss_conf.rss_hf != 0) {
		port->dev_conf.rxmode.mq_mode =
			(enum rte_eth_rx_mq_mode)
				(port_cfg[pid].rx_mq_mode & RTE_ETH_MQ_RX_RSS);
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
}

int rt_port_setup_config(portid_t pid)
{
	portid_t pi;
	uint32_t socket_id;
	struct port_config *ports_cfg = NULL;
	struct rte_port *port = NULL;
	int ret = 0;

	ports_cfg = port_get_config();
	port = rt_eth_get_port();

#if NUMA_SUPPORT
	socket_id = rte_eth_dev_socket_id(pid);

	/*
		* if socket_id is invalid,
		* set to the 0.
		*/
	if (check_socket_id(socket_id) < 0)
		socket_id = 0;
#else
	socket_id = 0;
#endif // NUMA_SUPPORT
		/* Apply default TxRx configuration for all ports */
	ret = config_port_setup_offloads(pid, socket_id);
	if (ret < 0)
		return -1;
	
	ret = port_setup_ex_config(pi);
	if (ret < 0)
		return -1;

	rxtx_port_config(pid);

	ret = eth_macaddr_get_print_err(pid, &port->eth_addr);
	if (ret != 0)
		return -1;
	// todo
	// if (ports_cfg[pid].lsc_interrupt && (port[pid].dev_info.dev_flags   & RTE_ETH_DEV_INTR_LSC))
	// 	port->dev_conf.intr_conf.lsc = 1;
	// if (ports_cfg[pid].rmv_interrupt && (port[pid].dev_info.dev_flags & RTE_ETH_DEV_INTR_RMV))
	// 	port->dev_conf.intr_conf.rmv = 1;

	return 0;
}

void add_rx_dump_callbacks(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	struct rte_port* port;
	int ret;

	if (port_id_is_invalid(portid))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	//todo
}

void add_tx_dump_callbacks(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	//todo
}

void remove_rx_dump_callbacks(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	//todo
}

void remove_tx_dump_callbacks(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	//todo
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
