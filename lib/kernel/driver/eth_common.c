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
#include "driver/eth_common.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_cfgfile.h>
#include <driver/rt_ethdev.h>
#include <driver/rt_ethdev_core.h>

#ifndef MAP_HUGETLB
/* FreeBSD may not have MAP_HUGETLB (in fact, it probably doesn't) */
#define HUGE_FLAG (0x40000)
#else
#define HUGE_FLAG MAP_HUGETLB
#endif

#ifndef MAP_HUGE_SHIFT
/* older kernels (or FreeBSD) will not have this define */
#define HUGE_SHIFT (26)
#else
#define HUGE_SHIFT MAP_HUGE_SHIFT
#endif

#define EXTMEM_HEAP_NAME "extmem"

/*
 * Zone size with the malloc overhead (max of debug and release variants)
 * must fit into the smallest supported hugepage size (2M),
 * so that an IOVA-contiguous zone of this size can always be allocated
 * if there are free 2M hugepages.
 */
#define EXTBUF_ZONE_SIZE (RTE_PGSIZE_2M - 4 * RTE_CACHE_LINE_SIZE)

struct extmem_param {
	void *addr;
	size_t len;
	size_t pgsz;
	rte_iova_t *iova_table;
	unsigned int iova_table_len;
};

int
port_id_is_invalid(portid_t port_id)
{
	uint16_t pid;

	if (port_id == (portid_t)RTE_PORT_ALL)
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
	if (numa_available() < 0 || numa_max_node() > socket_id) 
		return -1;
	return 0;
}

/* extremely pessimistic estimation of memory required to create a mempool */
static int calc_mem_size(uint32_t nb_mbufs, uint32_t mbuf_sz, size_t pgsz, size_t *out)
{
	unsigned int n_pages, mbuf_per_pg, leftover;
	uint64_t total_mem, mbuf_mem, obj_sz;

	/* there is no good way to predict how much space the mempool will
	 * occupy because it will allocate chunks on the fly, and some of those
	 * will come from default DPDK memory while some will come from our
	 * external memory, so just assume 128MB will be enough for everyone.
	 */
	uint64_t hdr_mem = 128 << 20;

	/* account for possible non-contiguousness */
	obj_sz = rte_mempool_calc_obj_size(mbuf_sz, 0, NULL);
	if (obj_sz > pgsz)
		return EINVAL;

	mbuf_per_pg = pgsz / obj_sz;
	leftover = (nb_mbufs % mbuf_per_pg) > 0;
	n_pages = (nb_mbufs / mbuf_per_pg) + leftover;

	mbuf_mem = n_pages * pgsz;

	total_mem = RTE_ALIGN(hdr_mem + mbuf_mem, pgsz);

	if (total_mem > SIZE_MAX)
		return EINVAL;

	*out = (size_t)total_mem;

	return 0;
}

static inline int pagesz_flags(uint64_t page_sz)
{
	/* as per mmap() manpage, all page sizes are log2 of page size
	 * shifted by MAP_HUGE_SHIFT
	 */
	int log2 = rte_log2_u64(page_sz);

	return (log2 << HUGE_SHIFT);
}

static void* alloc_mem(size_t memsz, size_t pgsz, bool huge)
{
	void *addr;
	int flags;

	/* allocate anonymous hugepages */
	flags = MAP_ANONYMOUS | MAP_PRIVATE;
	if (huge)
		flags |= HUGE_FLAG | pagesz_flags(pgsz);
	
	addr = mmap(NULL, memsz, PROT_READ | PROT_WRITE, flags, -1, 0);
	if (addr == MAP_FAILED)
		return NULL;
	
	return addr;
}

static int create_extmem(uint32_t nb_mbufs, uint32_t mbuf_sz, struct extmem_param *param,
		bool huge)
{
	uint64_t pgsizes[] = {RTE_PGSIZE_2M, RTE_PGSIZE_1G, /* x86_64, ARM */
			RTE_PGSIZE_16M, RTE_PGSIZE_16G};    /* POWER */
	unsigned int cur_page, n_pages, pgsz_idx;
	size_t mem_sz, cur_pgsz;
	rte_iova_t *iovas = NULL;
	void *addr;
	int ret;

	for (pgsz_idx = 0; pgsz_idx < RTE_DIM(pgsizes); pgsz_idx++) {
		/* skip anything that is too big */
		if (pgsizes[pgsz_idx] > SIZE_MAX)
			continue;
		
		cur_pgsz = pgsizes[pgsz_idx];

		if (!huge)
			cur_pgsz = sysconf(_SC_PAGESIZE);

		ret = calc_mem_size(nb_mbufs, mbuf_sz, cur_pgsz, &mem_sz);
		if (ret < 0)
			return -1;
		
		/* allocate our memory */
		addr = alloc_mem(mem_sz, cur_pgsz, huge);

		/* if we couldn't allocate memory with a specified page size,
		 * that doesn't mean we can't do it with other page sizes, so
		 * try another one.
		 */
		if (addr == NULL)
			continue;
		
		/* store IOVA addresses for every page in this memory area */
		n_pages = mem_sz / cur_pgsz;

		iovas = malloc(sizeof(*iovas) * n_pages);

		if (iovas == NULL) {
			goto fail;
		}
		/* lock memory if it's not huge pages */
		if (!huge)
			mlock(addr, mem_sz);
		
		/* populate IOVA addresses */
		for (cur_page = 0; cur_page < n_pages; cur_page++) {
			rte_iova_t iova;
			size_t offset;
			void *cur;

			offset = cur_pgsz * cur_page;
			cur = RTE_PTR_ADD(addr, offset);

			/* touch the page before getting its IOVA */
			*(volatile char *)cur = 0;

			iova = rte_mem_virt2iova(cur);

			iovas[cur_page] = iova;
		}

		break;
	}
	/* if we couldn't allocate anything */
	if (iovas == NULL)
		return -1;

	param->addr = addr;
	param->len = mem_sz;
	param->pgsz = cur_pgsz;
	param->iova_table = iovas;
	param->iova_table_len = n_pages;

	return 0;
fail:
	free(iovas);
	if (addr)
		munmap(addr, mem_sz);

	return -1;
}

static int setup_extmem(uint32_t nb_mbufs, uint32_t mbuf_sz, bool huge)
{
	struct extmem_param param;
	int socket_id, ret;

	memset(&param, 0, sizeof(param));

	/* check if our heap exists */
	socket_id = rte_malloc_heap_get_socket(EXTMEM_HEAP_NAME);
	if (socket_id < 0) {
		/* create our heap */
		ret = rte_malloc_heap_create(EXTMEM_HEAP_NAME);
		if (ret < 0) {
			return -1;
		}
	}

	ret = create_extmem(nb_mbufs, mbuf_sz, &param, huge);
	if (ret < 0) {
		TESTPMD_LOG(ERR, "Cannot create memory area\n");
		return -1;
	}

	/* we now have a valid memory area, so add it to heap */
	ret = rte_malloc_heap_memory_add(EXTMEM_HEAP_NAME,
			param.addr, param.len, param.iova_table,
			param.iova_table_len, param.pgsz);

	/* not needed any more */
	free(param.iova_table);

	if (ret < 0) {
		munmap(param.addr, param.len);
		return -1;
	}

	return 0;
}

static unsigned int setup_extbuf(uint32_t nb_mbufs, uint16_t mbuf_sz, unsigned int socket_id,
	    char *pool_name, struct rte_pktmbuf_extmem **ext_mem)
{
	struct rte_pktmbuf_extmem *xmem;
	unsigned int ext_num, zone_num, elt_num;
	uint16_t elt_size;

	elt_size = RTE_ALIGN_CEIL(mbuf_sz, RTE_CACHE_LINE_SIZE);
	elt_num = EXTBUF_ZONE_SIZE / elt_size;
	zone_num = (nb_mbufs + elt_num - 1) / elt_num;

	xmem = malloc(sizeof(struct rte_pktmbuf_extmem) * zone_num);
	if (xmem == NULL) {
		*ext_mem = NULL;
		return 0;
	}
	for (ext_num = 0; ext_num < zone_num; ++ext_num) {
		struct rte_pktmbuf_extmem *xseg = xmem + ext_num;
		const struct rte_memzone *mz;
		char mz_name[RTE_MEMZONE_NAMESIZE];
		int ret;

		ret = snprintf(mz_name, sizeof(mz_name),
			RTE_MEMPOOL_MZ_FORMAT "_xb_%u", pool_name, ext_num);
		if (ret < 0 || ret >= (int)sizeof(mz_name)) {
			errno = ENAMETOOLONG;
			ext_num = 0;
			break;
		}
		mz = rte_memzone_reserve(mz_name, EXTBUF_ZONE_SIZE,
					 socket_id,
					 RTE_MEMZONE_IOVA_CONTIG |
					 RTE_MEMZONE_1GB |
					 RTE_MEMZONE_SIZE_HINT_ONLY);
		if (mz == NULL) {
			/*
			 * The caller exits on external buffer creation
			 * error, so there is no need to free memzones.
			 */
			errno = ENOMEM;
			ext_num = 0;
			break;
		}
		xseg->buf_ptr = mz->addr;
		xseg->buf_iova = mz->iova;
		xseg->buf_len = EXTBUF_ZONE_SIZE;
		xseg->elt_size = elt_size;
	}
	if (ext_num == 0 && xmem != NULL) {
		free(xmem);
		xmem = NULL;
	}
	*ext_mem = xmem;
	return ext_num;
}

struct rte_mempool* rt_mktbuf_pool_create(const char* name, 
                        uint8_t mp_alloc_type, unsigned flags,
                        unsigned int mempool_cache,
                        uint16_t mbuf_size, unsigned nb_mbuf, 
                        unsigned int socket_id)
{
	struct rte_mempool *rte_mp = NULL;
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		rte_mp = rte_mempool_lookup(name);
		return rte_mp;
	}

	switch (mp_alloc_type) {
	case MP_ALLOC_NATIVE:
		{
			rte_mp = rte_pktmbuf_pool_create(name, nb_mbuf,
				mempool_cache, 0, mbuf_size, socket_id);
			break;
		}
	case MP_ALLOC_ANON:
		{
			rte_mp = rte_mempool_create_empty(name, nb_mbuf,
				mbuf_size, (unsigned int) mempool_cache,
				sizeof(struct rte_pktmbuf_pool_private),
				socket_id, flags);
			if (rte_mp == NULL)
				goto out;
			
			if (rte_mempool_populate_anon(rte_mp) == 0) {
				rte_mempool_free(rte_mp);
				rte_mp = NULL;
				goto out;
			}
			
			rte_pktmbuf_pool_init(rte_mp, NULL);
			rte_mempool_obj_iter(rte_mp, rte_pktmbuf_init, NULL);
			break;
		}
	case MP_ALLOC_XMEM:
	case MP_ALLOC_XMEM_HUGE:
		{
			int heap_socket;
			bool huge = mp_alloc_type == MP_ALLOC_XMEM_HUGE;

			if (setup_extmem(nb_mbuf, mbuf_seg_size, huge) < 0)
				//todo
				return -1;
			
			heap_socket = 
				rte_malloc_heap_get_socket(EXTMEM_HEAP_NAME);
			if (heap_socket < 0)
				//todo
				return -1;
			
			rte_mp = rte_pktmbuf_pool_create(name, nb_mbuf,
					mempool_cache, 0, mbuf_size,
					heap_socket);
			break;
		}
	case MP_ALLOC_XBUF:
		{
			struct rte_pktmbuf_extmem* ext_mem;
			unsigned int ext_num;

			ext_num = setup_extbuf(nb_mbuf,	mbuf_seg_size,
					       socket_id, pool_name, &ext_mem);
			if (ext_num == 0)
				//todo
				return -1;
			
			rte_mp = rte_pktmbuf_pool_create_extbuf
					(pool_name, nb_mbuf, mb_mempool_cache,
					 0, mbuf_seg_size, socket_id,
					 ext_mem, ext_num);
			free(ext_mem);
			break;
		}
	default:
		{
			//todo
		}
	}
out:
	return rte_mp;
}

#define SET_OPTIONAL_INT_CFG(target, cfg, entry, sec_name, entryname, type) do {	\
	entry = rte_cfgfile_get_entry(cfg, sec_name, #entryname);	\
	if (entry)
		target = (type)atoi(entry);
}

int cfg_load_port(struct rte_cfgfile* cfg)
{
	struct ethdev_config *ethdev_cfg = ethdev_get_config();
	const char *entry;
	const char *sec_name = "ethdev";
	unsigned int i = 0;

	if (!cfg)
		return -1;
	
	ret = rte_cfgfile_has_section(cfg, sec_name);
	if (ret)
		return -1;
	
	entry = rte_cfgfile_get_entry(cfg, sec_name, "socketid");
	if (entry) {
		char *next;

		for (i = 0; i < RTE_MAX_NUMA_NODES; ++i) {
			unsigned int socketid;
			ethdev_cfg->num_sockets++;
			socketid = (unsigned int)strtol(entry, &next, 10);
			if (socketid >= RTE_MAX_NUMA_NODES)
				return -1;
			ethdev_cfg->socket_ids[socketid] = 1;
			if (next == NULL)
				break;
			entry = next;
		}
	}

	entry = rte_cfgfile_get_entry(cfg, sec_name, "cpuid");
	if (entry) {
		char *next;

		for (i = 0; i < RTE_MAX_LCORE; ++i) {
			unsigned int cpuid;
			ethdev_cfg->num_cpuids++;
			cpuid = (unsigned int)strtol(entry, &next, 10);
			if (cpuid >= RTE_MAX_LCORE)
				return -1;
			ethdev_cfg->socket_ids[cpuid] = 1;
			if (next == NULL)
				break;
			entry = next;
		}
	}

	entry = rte_cfgfile_get_entry(cfg, sec_name, "nb_ports");
	if (!entry) {
		fprintf(stderr, "Cannot find nb_ports entry\n");
		return -1;
	}
	ethdev_cfg->nb_cfg_ports = atoi(entry);

	entry = rte_cfgfile_get_entry(cfg, sec_name, "loglevel");
	if (entry) {
		if (strcmp(entry, "debug") == 0) 
            ethdev_cfg->level = RTE_LOG_DEBUG;
        else if (strcmp(entry, "info") == 0)
            ethdev_cfg->level = RTE_LOG_INFO;
        else if (strcmp(entry, "warning") == 0)
            ethdev_cfg->level = RTE_LOG_WARNING;
        else if (strcmp(entry, "error") == 0)
            ethdev_cfg->level = RTE_LOG_ERR;
        else if (strcmp(entry, "critical") == 0)
            ethdev_cfg->level = RTE_LOG_CRIT;
	}

	entry = rte_cfgfile_get_entry(cfg, sec_name, "total_num_mbufs");
	if (entry)
		ethdev_cfg->total_num_mbufs = atoi(entry);
	
	entry = rte_cfgfile_get_entry(cfg, sec_name, "mp_alloc_type");
	if (entry) {
		if (strcmp(entry, "native") == 0)
             ethdev_cfg->mp_alloc_type = MP_ALLOC_NATIVE;
        else if (strcmp(entry, "anno") == 0)
             ethdev_cfg->mp_alloc_type = MP_ALLOC_ANON;
        else if (strcmp(entry, "xmem") == 0)
             ethdev_cfg->mp_alloc_type = MP_ALLOC_XMEM;
        else if (strcmp(entry, "xmem_huge") == 0)
             ethdev_cfg->mp_alloc_type = MP_ALLOC_XMEM_HUGE;
        else if (strcmp(entry, "xbuf") == 0)
             ethdev_cfg->mp_alloc_type = MP_ALLOC_XBUF;
	}

	entry = rte_cfgfile_get_entry(cfg, sec_name, "mp_create_type");
	if (entry) {
		if (strcmp(entry, "per_socket") == 0)
             ethdev_cfg->mp_create_type = MP_PER_SOCKET;
        else if (strcmp(entry, "per_core") == 0)
             ethdev_cfg->mp_create_type = MP_PER_CORE;
        else if (strcmp(entry, "per_queue") == 0)
             ethdev_cfg->mp_create_type = MP_PER_QUEUE;
	}

	entry = rte_cfgfile_get_entry(cfg, sec_name, "mb_mempool_cache");
	if (entry) 
		ethdev_cfg->mb_mempool_cache = atoi(entry);
	
	entry = rte_cfgfile_get_entry(cfg, sec_name, "mempool_flag");
	if (entry) {
		do {
			char mp_flag[100];
			const char* end = strstr(entry, ",");
			if (end == NULL)
				break;
			memset(mp_flag, 0, 100);
			strncpy(mp_flag, entry, end - entry);
			if (strcmp(mp_flag, "no_spread") == 0) 
				ethdev_cfg->mempool_flag |= RTE_MEMPOOL_F_NO_SPREAD;
			else if (strcmp(mp_flag, "no_cache_align") == 0)
				ethdev_cfg->mempool_flag |= RTE_MEMPOOL_F_NO_CACHE_ALIGN;
			else if (strcmp(mp_flag, "sp_put") == 0)
				ethdev_cfg->mempool_flag |= RTE_MEMPOOL_F_SP_PUT;
			else if (strcmp(mp_flag, "sc_get") == 0)
				ethdev_cfg->mempool_flag |= RTE_MEMPOOL_F_SC_GET;
			entry = end + 1;
		} while (1);
	}

	return 0;
}

static void port_parse_rx_offloads(struct rte_cfgfile * cfg, const char* sec_name, uint64_t *offloads)
{
	char *entry = NULL;

	entry = rte_cfgfile_get_entry(cfg, sec_name, "rx_offloads");
	if (entry) {
		do {
			char offloads_str[100];
			const char * end = strstr(entry, ",");
			if (end == NULL)
				break;
			memset(offloads_str, 0, 100);
			strncpy(offloads_str, entry, end - entry);
			if (strcmp(offloads_str, "vlan_strip") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
			else if (strcmp(offloads_str, "ipv4_cksum") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
			else if (strcmp(offloads_str, "udp_cksum") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_UDP_CKSUM;
			else if (strcmp(offloads_str, "tcp_cksum") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_TCP_CKSUM;
			else if (strcmp(offloads_str, "tcp_lro") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_TCP_LRO;
			else if (strcmp(offloads_str, "qinq_strip") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_QINQ_STRIP;
			else if (strcmp(offloads_str, "outer_ipv4_cksum") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM;
			else if (strcmp(offloads_str, "macsec_strip") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_MACSEC_STRIP;
			else if (strcmp(offloads_str, "vlan_filter") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_VLAN_FILTER;
			else if (strcmp(offloads_str, "vlan_extend") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_VLAN_EXTEND;
			else if (strcmp(offloads_str, "scatter") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_SCATTER;
			else if (strcmp(offloads_str, "timestamp") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
			else if (strcmp(offloads_str, "security") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_SECURITY;
			else if (strcmp(offloads_str, "keep_crc") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_KEEP_CRC;
			else if (strcmp(offloads_str, "sctp_cksum") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_SCTP_CKSUM;
			else if (strcmp(offloads_str, "outer_udp_cksum") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM;
			else if (strcmp(offloads_str, "rss_hash") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_RSS_HASH;
			else if (strcmp(offloads_str, "buffer_split") == 0)
				*offloads |= RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT;
			entry = end + 1;
		}
	}
}

static void port_parse_tx_offloads(struct rte_cfgfile * cfg, const char* sec_name, uint64_t *offloads)
{
	char *entry = NULL;

	entry = rte_cfgfile_get_entry(cfg, sec_name, "rx_offloads");
	if (entry) {
		do {
			char offloads_str[100];
			const char * end = strstr(entry, ",");
			if (end == NULL)
				break;
			memset(offloads_str, 0, 100);
			strncpy(offloads_str, entry, end - entry);
			if (strcmp(offloads_str, "vlan_insert") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_VLAN_INSERT;
			else if (strcmp(offloads_str, "ipv4_cksum") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
			else if (strcmp(offloads_str, "udp_cksum") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
			else if (strcmp(offloads_str, "tcp_cksum") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
			else if (strcmp(offloads_str, "sctp_cksum") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_SCTP_CKSUM;
			else if (strcmp(offloads_str, "tcp_tso") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_TCP_TSO;
			else if (strcmp(offloads_str, "udp_tso") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_UDP_TSO;
			else if (strcmp(offloads_str, "outer_ipv4_cksum") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM;
			else if (strcmp(offloads_str, "qinq_insert") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_QINQ_INSERT;
			else if (strcmp(offloads_str, "vxla_tnl_tso") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO;
			else if (strcmp(offloads_str, "tnl_tso") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO;
			else if (strcmp(offloads_str, "tnl_tsp") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO;
			else if (strcmp(offloads_str, "geneve_tnl_tso") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO;
			else if (strcmp(offloads_str, "macsec_insert") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_MACSEC_INSERT;
			else if (strcmp(offloads_str, "mt_lockfree") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_MT_LOCKFREE;
			else if (strcmp(offloads_str, "multi_segs") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
			else if (strcmp(offloads_str, "fast_free") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
			else if (strcmp(offloads_str, "security") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_SECURITY;
			else if (strcmp(offloads_str, "tnl_tso") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_UDP_TNL_TSO;
			else if (strcmp(offloads_str, "tnl_tso") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_IP_TNL_TSO;
			else if (strcmp(offloads_str, "udp_cksum") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM;
			else if (strcmp(offloads_str, "timstamp") == 0)
				*offloads |= RTE_ETH_TX_OFFLOAD_SEND_ON_TIMESTAMP;
			entry = end + 1;
		}
	}
}

#define CFG_NAME_LEN 100
int cfg_load_subport(struct rte_cfgfile * cfg)
{
	unsigned int i = 0;
	struct port_config * ports_cfg = port_get_config();

	for (i = 0; i < RTE_MAX_ETHPORTS; ++i) {
		char sec_name[CFG_NAME_LEN];
		char *entry = NULL;
		unsigned int rx_desc_cnt = 0, tx_desc_cnt = 0;
		char *next = NULL;
		snprintf(sec_name, sizeof(sec_name), "subport %d", i);

		if (rte_cfgfile_has_section(cfg, sec_name)) {
			struct port_config *port_cfg = &ports_cfg[i];
			port_cfg->selected = 1;
			SET_OPTIONAL_INT_CFG(port_c fg->rxring_numa, cfg, entry, sec_name, rxring_numa, uint8_t);
			SET_OPTIONAL_INT_CFG(port_cfg->txring_numa, cfg, entry, sec_name, txring_numa, uint8_t);
			SET_OPTIONAL_INT_CFG(port_cfg->nb_rxd, cfg, entry, sec_name, nb_rxd, uint16_t);
			SET_OPTIONAL_INT_CFG(port_cfg->nb_txd, cfg, entry, sec_name, nb_txd, uint16_t);
			SET_OPTIONAL_INT_CFG(port_cfg->nb_rxq, cfg, entry, sec_name, nb_rxq, queueid_t);
			SET_OPTIONAL_INT_CFG(port_cfg->nb_txq, cfg, entry, sec_name, nb_txq, queueid_t);
			SET_OPTIONAL_INT_CFG(port_cfg->rx_free_thresh, cfg, entry, sec_name, rx_free_thresh, uint16_t);
			SET_OPTIONAL_INT_CFG(port_cfg->rx_drop_en, cfg, entry, sec_name, rx_drop_en, uint8_t);
			SET_OPTIONAL_INT_CFG(port_cfg->tx_free_thresh, cfg, entry, sec_name, tx_free_thresh, uint16_t);
			SET_OPTIONAL_INT_CFG(port_cfg->tx_rs_thresh, cfg, entry, sec_name, tx_rs_thresh, uint16_t);
			SET_OPTIONAL_INT_CFG(port_cfg->eth_link_speed, cfg, entry, sec_name, eth_link_speed, uint32_t);
			SET_OPTIONAL_INT_CFG(port_cfg->rx_pthresh, cfg, entry, sec_name, rx_pthresh, uint8_t);
			SET_OPTIONAL_INT_CFG(port_cfg->rx_hthresh, cfg, entry, sec_name, rx_hthresh, uint8_t);
			SET_OPTIONAL_INT_CFG(port_cfg->rx_wthresh, cfg, entry, sec_name, rx_wthresh, uint8_t);
			SET_OPTIONAL_INT_CFG(port_cfg->tx_pthresh, cfg, entry, sec_name, tx_pthresh, uint8_t);
			SET_OPTIONAL_INT_CFG(port_cfg->tx_hthresh, cfg, entry, sec_name, tx_hthresh, uint8_t);
			SET_OPTIONAL_INT_CFG(port_cfg->tx_wthresh, cfg, entry, sec_name, tx_wthresh, uint8_t);
			SET_OPTIONAL_INT_CFG(port_cfg->lsc_interrupt, cfg, entry, sec_name, lsc_interrupt, uint8_t);
			SET_OPTIONAL_INT_CFG(port_cfg->no_link_check, cfg, entry, sec_name, no_link_check, uint8_t);
			SET_OPTIONAL_INT_CFG(port_cfg->promiscuous_enable, cfg, entry, sec_name, promiscuous_enable, int);

			port_parse_rx_offloads(cfg, sec_name, &port_cfg->rx_mode.offloads);
			port_parse_tx_offloads(cfg, sec_name, &port_cfg->tx_mode.offloads);

			entry = rte_cfgfile_get_entry(cfg, sec_name, "rx_desc");
			if (entry == NULL)
				return -1;
			do {
				char rx_desc[100];
				next = strstr(entry, ",");
				if (next == NULL)
					break;
				strncpy(rx_desc, entry, next - entry);
				port_cfg->nb_rx_desc[rx_desc_cnt++] = (uint16_t)atoi(rx_desc);
				entry = next + 1;
			} while (1);

			if (rx_desc_cnt != port_cfg->nb_rxd)
				return -1;
			
			entry = rte_cfgfile_get_entry(cfg, sec_name, "tx_desc");
			if (entry == NULL)
				return -1;
			do {
				char tx_desc[100];
				next = strstr(entry, ",");
				if (next == NULL)
					break;
				strncpy(rx_desc, entry, next - entry);
				port_cfg->nb_rx_desc[tx_desc_cnt++] = (uint16_t)atoi(rx_desc);
				entry = next + 1;
			} while (1);

			if (tx_desc_cnt != port_cfg->nb_txd)
				return -1;
		}
	}
}