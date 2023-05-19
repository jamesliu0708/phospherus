#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_mbuf_pool_ops.h>
#include <rte_cfgfile.h>
#include <rte_kni.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <pss_port.h>
#include "rte_eth.h"
#include "rte_eth_config.h"
#include "rte_eth_core.h"
#include "rte_rxtx.h"
#include "eth_common.h"

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

static struct rte_mempool *dev_mpool[RTE_MAX_NUMA_NODES * MAX_SEGS_BUFFER_SPLIT];

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
	flags = MAP_PRIVATE;
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
		fprintf(stderr, "Cannot create memory area\n");
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
	    const char *pool_name, struct rte_pktmbuf_extmem **ext_mem)
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

#define SET_OPTIONAL_INT_CFG(target, cfg, entry, sec_name, entryname, type) do {	\
	entry = rte_cfgfile_get_entry(cfg, sec_name, #entryname);	\
	if (entry)	\
		target = (type)atoi(entry);	\
} while (0)

static void rte_mp_cfg_setup(struct rte_cfgfile *file, const char* sec_name, struct mbuf_pool_configure *mbp_cfg)
{
	const char* entry = NULL;

	entry = rte_cfgfile_get_entry(file, sec_name, "total_num_mbufs");
	if (entry)
		mbp_cfg->total_num_mbufs = atoi(entry);

	entry = rte_cfgfile_get_entry(file, sec_name, "mb_mempool_cache");
	if (entry)
		mbp_cfg->mb_mempool_cache = atoi(entry);
	
	entry = rte_cfgfile_get_entry(file, sec_name, "mp_alloc_type");
	if (entry) {
		if (strcmp(entry, MP_ALLOC_NATIVE_STR) == 0)
             mbp_cfg->alloc_type = MP_ALLOC_NATIVE;
        else if (strcmp(entry, MP_ALLOC_ANON_STR) == 0)
             mbp_cfg->alloc_type = MP_ALLOC_ANON;
        else if (strcmp(entry, MP_ALLOC_XMEM_STR) == 0)
             mbp_cfg->alloc_type = MP_ALLOC_XMEM;
        else if (strcmp(entry, MP_ALLOC_XMEM_HUGE_STR) == 0)
             mbp_cfg->alloc_type = MP_ALLOC_XMEM_HUGE;
        else if (strcmp(entry, MP_ALLOC_XBUF_STR) == 0)
             mbp_cfg->alloc_type = MP_ALLOC_XBUF;
	}

	entry = rte_cfgfile_get_entry(file, sec_name, "mempool_flag");
	if (entry) {
		do {
			char mp_flag[100];
			const char* end = strstr(entry, ",");
			if (end == NULL)
				break;
			memset(mp_flag, 0, 100);
			strncpy(mp_flag, entry, end - entry);
			if (strcmp(mp_flag, "no_spread") == 0) 
				mbp_cfg->mp_flag |= RTE_MEMPOOL_F_NO_SPREAD;
			else if (strcmp(mp_flag, "no_cache_align") == 0)
				mbp_cfg->mp_flag |= RTE_MEMPOOL_F_NO_CACHE_ALIGN;
			else if (strcmp(mp_flag, "sp_put") == 0)
				mbp_cfg->mp_flag |= RTE_MEMPOOL_F_SP_PUT;
			else if (strcmp(mp_flag, "sp_get") == 0)
				mbp_cfg->mp_flag |= RTE_MEMPOOL_F_SC_GET;
			entry = end + 1;
		} while (1);
	}
}

/*
 * Configuration initialisation done once at init time.
 */
static struct rte_mempool * mbuf_pool_create(const char* pool_name, const char* alloc_op_name, 
				uint16_t mbuf_seg_size, struct mbuf_pool_configure* mbcfg, unsigned nb_mbuf, unsigned int socket_id)
{
	struct rte_mempool *rte_mp = NULL;
	int ret = 0;

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
	
	switch (mbcfg->alloc_type) {
	case MP_ALLOC_NATIVE:
		{
			rte_mp = rte_pktmbuf_pool_create_by_ops(pool_name, nb_mbuf, 
							(unsigned int) mbcfg->mb_mempool_cache, 0, mbuf_seg_size, socket_id, alloc_op_name);
			break;
		}
	case MP_ALLOC_ANON:
		{
			rte_mp = rte_mempool_create_empty(pool_name, nb_mbuf,
				mbuf_seg_size, (unsigned int) mbcfg->mb_mempool_cache,
				sizeof(struct rte_pktmbuf_pool_private),
				socket_id, (unsigned int) mbcfg->mp_flag);
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
			bool huge = mbcfg->alloc_type == MP_ALLOC_XMEM_HUGE;

			if (setup_extmem(nb_mbuf, mbuf_seg_size, huge) < 0)
				rte_exit(EXIT_FAILURE, "Could not create external memory\n");

			heap_socket =
				rte_malloc_heap_get_socket(EXTMEM_HEAP_NAME);
			if (heap_socket < 0)
				rte_exit(EXIT_FAILURE, "Could not get external memory socket ID\n");

			rte_mp = rte_pktmbuf_pool_create_by_ops(pool_name, nb_mbuf,
					(unsigned int) mbcfg->mb_mempool_cache, 0, mbuf_seg_size,
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
					(pool_name, nb_mbuf, (unsigned int)mbcfg->mb_mempool_cache,
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

/* Mbuf Pools */
static inline void
mbuf_poolname_build(unsigned int sock_id, char *mp_name,
		    int name_size, uint16_t idx)
{
	if (idx != (uint16_t)-1)
		snprintf(mp_name, name_size,
			 MBUF_POOL_NAME_PFX "_%u", sock_id);
	else
		snprintf(mp_name, name_size,
			 MBUF_POOL_NAME_PFX "_%hu_%hu", (uint16_t)sock_id, idx);
}

static inline struct rte_mempool *mbuf_pool_find(unsigned int tag_id, uint16_t idx)
{
	char pool_name[RTE_MEMPOOL_NAMESIZE];

	mbuf_poolname_build(tag_id, pool_name, sizeof(pool_name), idx);
	return rte_mempool_lookup((const char *)pool_name);
}

static int
get_eth_overhead(struct rte_eth_dev_info *dev_info)
{
	uint32_t eth_overhead;

	if (dev_info->max_mtu != UINT16_MAX &&
	    dev_info->max_rx_pktlen > dev_info->max_mtu)
		eth_overhead = dev_info->max_rx_pktlen - dev_info->max_mtu;
	else
		eth_overhead = RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;

	return eth_overhead;
}

int rte_load_gcfg(const char *profile) 
{
	const char* sec_name;
	int ret = 0;
	const char* entry;
	unsigned int i = 0;
	uint16_t pid;
	struct rte_eth_link link;
	struct rte_cfgfile *file = NULL;
	struct rte_ethlayer_configure* ethcfg = rte_gethdev_get_config();

	if (profile == NULL)
		return 0;
	file = rte_cfgfile_load(profile, 0);
	if (file == NULL) 
		return -1;
	
	sec_name = "genv";
	ret = rte_cfgfile_has_section(file, sec_name);
	if (ret)
		goto _app_load_cfg_profile_error_return;

	entry = rte_cfgfile_get_entry(file, sec_name, "loglevel");
	if (entry) {
		
		if (strcmp(entry, "debug") == 0) 
            ethcfg->log_level = RTE_LOG_DEBUG;
        else if (strcmp(entry, "info") == 0)
            ethcfg->log_level = RTE_LOG_INFO;
        else if (strcmp(entry, "warning") == 0)
            ethcfg->log_level = RTE_LOG_WARNING;
        else if (strcmp(entry, "error") == 0)
            ethcfg->log_level = RTE_LOG_ERR;
        else if (strcmp(entry, "critical") == 0)
            ethcfg->log_level = RTE_LOG_CRIT;

		ret = rt_eth_log_setup("rt_ethdev", ethcfg->log_level);
		if (ret < 0) {
			fprintf(stderr, "rt_ethdev: Cannot register log type\n");
			return ret;
		}
	}

	rte_mp_cfg_setup(file, sec_name, &ethcfg->gmbp);

	RTE_ETH_FOREACH_DEV(pid) {
		uint16_t mtu;
		struct rte_eth_dev_info dev_info;

		ret = rte_eth_link_get_nowait(pid, &link);
		if (ret < 0)
			continue;

		ret = eth_dev_info_get_print_err(pid, &dev_info);
		if (ret != 0) {
			RT_ETHDEV_LOG(ERR, "rte_eth_dev_info_get() failed\n");
			continue;
		}
		
		if (dev_info.rx_desc_lim.nb_mtu_seg_max != UINT16_MAX &&
	    	dev_info.rx_desc_lim.nb_mtu_seg_max != 0) {
			uint32_t eth_overhead = get_eth_overhead(&dev_info);

			if (rte_eth_dev_get_mtu(pid, &mtu) == 0) {
				uint16_t data_size = (mtu + eth_overhead) /
					dev_info.rx_desc_lim.nb_mtu_seg_max;
				uint16_t buffer_size = data_size + RTE_PKTMBUF_HEADROOM;

				if (buffer_size > ethcfg->gmbp.mbuf_data_size[0]) {
					ethcfg->gmbp.mbuf_data_size[0] = buffer_size;
					RT_ETHDEV_LOG(WARNING,
						"Configured mbuf size of the first segment %hu\n",
						ethcfg->gmbp.mbuf_data_size[0]);
				}
			}
		}
	}
	
	for (i = 0; i < RTE_MAX_NUMA_NODES; ++i) {
		char pool_name[100];
		unsigned int nb_mbuf_per_pool;

		if (ethcfg->socket[i] == 0) 
			continue;
		mbuf_poolname_build(0, pool_name, sizeof(pool_name), -1);
		if (ethcfg->gmbp.total_num_mbufs)
			nb_mbuf_per_pool = ethcfg->gmbp.total_num_mbufs;
		else {
			nb_mbuf_per_pool = RX_DESC_MAX +
				(rte_lcore_count() * ethcfg->gmbp.mb_mempool_cache) +
				TX_DESC_MAX + MAX_PKT_BURST;
			nb_mbuf_per_pool *= RTE_MAX_ETHPORTS;
		}

		dev_mpool[i * MAX_SEGS_BUFFER_SPLIT] = mbuf_pool_create(pool_name, NULL, ethcfg->gmbp.mbuf_data_size[0], 
												&ethcfg->gmbp, i, nb_mbuf_per_pool);
	}
	
	return ret;
_app_load_cfg_profile_error_return:
	rte_cfgfile_close(file);

	return ret;
}

static void rte_rst_gconfig(void)
{
	struct rte_ethlayer_configure* ethcfg = rte_gethdev_get_config();
	ethcfg->log_type = -1;
	ethcfg->log_level = RTE_LOG_DEBUG;
	memset(ethcfg->socket, 0, sizeof(ethcfg->socket));
	ethcfg->gmbp.total_num_mbufs = 0;
	ethcfg->gmbp.mbuf_data_size_n = 1;
	memset(ethcfg->gmbp.mbuf_data_size, 0, sizeof(ethcfg->gmbp.mbuf_data_size));
	ethcfg->gmbp.mbuf_data_size[0] = DEFAULT_MBUF_DATA_SIZE;
	ethcfg->gmbp.mb_mempool_cache = 0;
	ethcfg->gmbp.alloc_type = MP_ALLOC_NATIVE;
	ethcfg->gmbp.mp_flag = 0;
}

static void rte_rst_eth_cfg(uint16_t pid)
{
	struct rte_ethdev_configure *ethcfg = rte_eth_get_config(pid);
	if (ethcfg == NULL)
		return;
	
	ethcfg->port_id = pid;
	ethcfg->ex_mbp = 0;
	ethcfg->nb_rxd = RX_DESC_DEFAULT;
	ethcfg->nb_txd = TX_DESC_DEFAULT;
	ethcfg->nb_rxq = 1;
	ethcfg->nb_txq = 1;
	ethcfg->rx_free_thresh = RTE_PARAM_UNSET;
	ethcfg->rx_drop_en = RTE_PARAM_UNSET;
	ethcfg->tx_free_thresh = RTE_PARAM_UNSET;
	ethcfg->tx_rs_thresh = RTE_PARAM_UNSET;
	ethcfg->rx_pthresh = RTE_PARAM_UNSET;
	ethcfg->tx_hthresh = RTE_PARAM_UNSET;
	ethcfg->rx_wthresh = RTE_PARAM_UNSET;
	ethcfg->tx_pthresh = RTE_PARAM_UNSET;
	ethcfg->tx_hthresh = RTE_PARAM_UNSET;
	ethcfg->tx_wthresh = RTE_PARAM_UNSET;
	ethcfg->lsc_interrupt = 0;
	ethcfg->no_link_check = 1;
	ethcfg->promiscuous_enable = 0;
}

void rte_rst_config(uint16_t pid)
{
	uint16_t i;
	struct rte_ethdev_configure* ethcfg = rte_eth_get_config(pid);

	if (pid == RTE_PORT_ALL) {
		rte_rst_gconfig();
		
		for (i = 0; i < RTE_MAX_ETHPORTS; ++i) {
			rte_rst_eth_cfg(i);
		}
	} else 
		rte_rst_eth_cfg(pid);
	
}

int rte_gcfg_setup(const char* gpath)
{
	int ret = 0;
	struct rte_ethlayer_configure* rte_gcfg = NULL;

	ret = rte_load_gcfg(gpath);
	if (ret < 0) {
		fprintf(stderr, "Cannot load rte global cfgfile\n");
		return ret;
	}

	return 0;
}

int rt_eth_log_setup(const char* logname, uint32_t level)
{
	int ret = -1;
	struct rte_ethlayer_configure* p_cfg = rte_gethdev_get_config();
	p_cfg->log_type = rte_log_register(logname);
	if (p_cfg->log_type < 0)
		return p_cfg->log_type;
	ret = rte_log_set_level(p_cfg->log_type, level);
	return ret == 0? p_cfg->log_type: -1;
}

static void rx_offloads_parse(struct rte_cfgfile * cfg, const char* sec_name, uint64_t *offloads)
{
	const char *entry = NULL;

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
		} while (true);
	}
}

static void tx_offloads_parse(struct rte_cfgfile * cfg, const char* sec_name, uint64_t *offloads)
{
	const char *entry = NULL;

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
		} while (true);
	}
}

static int rte_eth_load_config(const char* ifname, uint16_t portid) {
	char if_cfgpath[100];
	char sec_name[64];
	char *next = NULL;
	const char *entry = NULL;
	unsigned int rx_desc_cnt = 0, tx_desc_cnt = 0;
	struct rte_cfgfile *file = NULL;
	struct rte_ethdev_configure *ethcfg = rte_eth_get_config(portid);

	snprintf(if_cfgpath, sizeof(if_cfgpath), "%s/%s", RTE_ETHERNET_DIR, ifname);
	file = rte_cfgfile_load(if_cfgpath, 0);
	if (file == NULL) 
		return -1;

	snprintf(sec_name, sizeof(sec_name), "%s", ifname);
	if (!rte_cfgfile_has_section(file, sec_name))
		return -1;
	
	SET_OPTIONAL_INT_CFG(ethcfg->nb_rxd, file, entry, sec_name, kni_ifaces, int);
	SET_OPTIONAL_INT_CFG(ethcfg->nb_rxd, file, entry, sec_name, nb_rxd, uint16_t);
	SET_OPTIONAL_INT_CFG(ethcfg->nb_txd, file, entry, sec_name, nb_txd, uint16_t);
	SET_OPTIONAL_INT_CFG(ethcfg->nb_rxq, file, entry, sec_name, nb_rxq, uint16_t);
	SET_OPTIONAL_INT_CFG(ethcfg->nb_txq, file, entry, sec_name, nb_txq, uint16_t);
	SET_OPTIONAL_INT_CFG(ethcfg->rx_free_thresh, file, entry, sec_name, rx_free_thresh, uint16_t);
	SET_OPTIONAL_INT_CFG(ethcfg->rx_drop_en, file, entry, sec_name, rx_drop_en, uint8_t);
	SET_OPTIONAL_INT_CFG(ethcfg->tx_free_thresh, file, entry, sec_name, tx_free_thresh, uint16_t);
	SET_OPTIONAL_INT_CFG(ethcfg->tx_rs_thresh, file, entry, sec_name, tx_rs_thresh, uint16_t);
	SET_OPTIONAL_INT_CFG(ethcfg->eth_link_speed, file, entry, sec_name, eth_link_speed, uint32_t);
	SET_OPTIONAL_INT_CFG(ethcfg->rx_pthresh, file, entry, sec_name, rx_pthresh, uint8_t);
	SET_OPTIONAL_INT_CFG(ethcfg->rx_hthresh, file, entry, sec_name, rx_hthresh, uint8_t);
	SET_OPTIONAL_INT_CFG(ethcfg->rx_wthresh, file, entry, sec_name, rx_wthresh, uint8_t);
	SET_OPTIONAL_INT_CFG(ethcfg->tx_pthresh, file, entry, sec_name, tx_pthresh, uint8_t);
	SET_OPTIONAL_INT_CFG(ethcfg->tx_hthresh, file, entry, sec_name, tx_hthresh, uint8_t);
	SET_OPTIONAL_INT_CFG(ethcfg->tx_wthresh, file, entry, sec_name, tx_wthresh, uint8_t);
	SET_OPTIONAL_INT_CFG(ethcfg->lsc_interrupt, file, entry, sec_name, lsc_interrupt, uint8_t);
	SET_OPTIONAL_INT_CFG(ethcfg->no_link_check, file, entry, sec_name, no_link_check, uint8_t);
	SET_OPTIONAL_INT_CFG(ethcfg->promiscuous_enable, file, entry, sec_name, promiscuous_enable, int);
	rx_offloads_parse(file, sec_name, &ethcfg->rx_mode.offloads);
	tx_offloads_parse(file, sec_name, &ethcfg->tx_mode.offloads);

	entry = rte_cfgfile_get_entry(file, sec_name, "rx_desc");
	if (entry == NULL)
		return -1;
	do {
		char rx_desc[100];
		next = strstr(entry, ",");
		if (next == NULL)
			break;
		strncpy(rx_desc, entry, next - entry);
		ethcfg->nb_rx_desc[rx_desc_cnt++] = (uint16_t)atoi(rx_desc);
		entry = next + 1;
	} while (1);

	entry = rte_cfgfile_get_entry(file, sec_name, "tx_desc");
	if (entry == NULL)
		return -1;
	do {
		char tx_desc[100];
		next = strstr(entry, ",");
		if (next == NULL)
			break;
		strncpy(tx_desc, entry, next - entry);
		ethcfg->nb_rx_desc[tx_desc_cnt++] = (uint16_t)atoi(tx_desc);
		entry = next + 1;
	} while (1);

	snprintf(sec_name, sizeof(sec_name), "%s", "ex-mbp");
	if (rte_cfgfile_has_section(file, sec_name)) {
		char pool_name[100];
		uint16_t socketid = rte_eth_dev_socket_id(portid);
		ethcfg->mbp.mp_flag = 1;
		rte_mp_cfg_setup(file, sec_name, &ethcfg->mbp);
		mbuf_poolname_build(socketid, pool_name, sizeof(pool_name), portid);
	}
	
	return 0;
}

static int eth_dev_start_mp(uint16_t port_id)
{
	int ret;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ret = rte_eth_dev_start(port_id);
		if (ret != 0)
			return ret;
	}
	
	return 0;
}

static int
eth_dev_configure_mp(uint16_t port_id, uint16_t nb_rx_q, uint16_t nb_tx_q,
		      const struct rte_eth_conf *dev_conf)
{
	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		return rte_eth_dev_configure(port_id, nb_rx_q, nb_tx_q,
					dev_conf);
	return 0;
}

int rte_port_start(uint16_t pid, struct rte_port* port)
{
	int diag;
	unsigned int i;
	uint16_t qi;
	struct rte_ethdev_configure* p_cfg = rte_eth_get_config(pid);

	if (port->port_status == RTE_PORT_STOPPED)
			port->port_status = RTE_PORT_HANDLING;
	else {
		RT_ETHDEV_LOG(ERR, "Port %d is now not stopped\n", pid);
		return -1;
	}

	if (port->need_reconfig > 0) {
		struct rte_eth_conf dev_conf;
		port->need_reconfig = 0;

		/* configure port */
		diag = eth_dev_configure_mp(pid, p_cfg->nb_rxq, p_cfg->nb_txq,
							&(port->dev_conf));
		if (diag != 0) {
			if (port->port_status == RTE_PORT_HANDLING)
				port->port_status = RTE_PORT_STOPPED;
			else
				RT_ETHDEV_LOG(ERR,
					"Port %d can not be set back to stopped\n",
					pid);
			RT_ETHDEV_LOG(ERR, "Fail to configure port %d\n",
				pid);
			/* try to reconfigure port next time */
			port->need_reconfig = 1;
			return -1;
		}
		/* get device configuration*/
		if (0 !=
			eth_dev_info_get_print_err(pid, &port->dev_info)) {
			RT_ETHDEV_LOG(ERR,
				"port %d can not get device configuration\n",
				pid);
			return -1;
		}
		/* Apply Rx offloads configuration */
		if (dev_conf.rxmode.offloads !=
			port->dev_conf.rxmode.offloads) {
			port->dev_conf.rxmode.offloads |=
				dev_conf.rxmode.offloads;
			for (i = 0;
					i < port->dev_info.max_rx_queues;
					i++)
				port->rxq[i].conf.offloads |=
					dev_conf.rxmode.offloads;
		}
		/* Apply Tx offloads configuration */
		if (dev_conf.txmode.offloads !=
			port->dev_conf.txmode.offloads) {
			port->dev_conf.txmode.offloads |=
				dev_conf.txmode.offloads;
			for (i = 0;
					i < port->dev_info.max_tx_queues;
					i++)
				port->txq[i].conf.offloads |=
					dev_conf.txmode.offloads;
		}
	}
	if (port->need_reconfig_queues > 0) {
		unsigned int tag_id = 0;
		struct rte_mempool *mp = NULL;
		uint16_t idx = p_cfg->ex_mbp ? pid: (uint16_t)-1;
		port->need_reconfig_queues = 0;
		
		mp = mbuf_pool_find(rte_eth_dev_socket_id(pid), idx);

		/* setup tx queues */
		for (qi = 0; qi < p_cfg->nb_txq; qi++) {
			port->txq[qi].mbp = mp;
			struct rte_eth_txconf *conf =
						&port->txq[qi].conf;
			diag = rte_eth_tx_queue_setup(pid, qi,
						port->nb_tx_desc[qi],
						rte_eth_dev_socket_id(pid),
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
						pid);
			RT_ETHDEV_LOG(ERR,
				"Fail to configure port %d tx queues\n",
				pid);
			/* try to reconfigure queues next time */
			port->need_reconfig_queues = 1;
			return -1;
		}
		for (qi = 0; qi < p_cfg->nb_rxq; qi++) {
			/* setup rx queues */
			port->rxq[qi].mbp = mp;
			/* Single pool/segment configuration */
			port->rxq[qi].conf.rx_seg = NULL;
			port->rxq[qi].conf.rx_nseg = 0;
			port->rxq[qi].conf.rx_mempools = NULL;
			port->rxq[qi].conf.rx_nmempool = 0;
			diag = rte_eth_rx_queue_setup(pid, qi, p_cfg->nb_rx_desc[qi],
						rte_eth_dev_socket_id(pid), &port->rxq[qi].conf, mp);
			if (diag == 0)
				continue;
			
			/* Fail to setup rx queue, return */
			if (port->port_status == RTE_PORT_HANDLING)
				port->port_status = RTE_PORT_STOPPED;
			else
				RT_ETHDEV_LOG(ERR,
					"Port %d can not be set back to stopped\n",
					pid);
			RT_ETHDEV_LOG(ERR,
				"Fail to configure port %d rx queues\n",
				pid);
			/* try to reconfigure queues next time */
			port->need_reconfig_queues = 1;
			return -1;
		}
	}

	/* start port */
	diag = eth_dev_start_mp(pid);
	if (diag < 0) {
		RT_ETHDEV_LOG(ERR, "Fail to start port %d: %s\n",
			pid, rte_strerror(-diag));

		/* Fail to setup rx queue, return */
		if (port->port_status == RTE_PORT_HANDLING)
			port->port_status = RTE_PORT_STOPPED;
		else
			RT_ETHDEV_LOG(ERR,
				"Port %d can not be set back to stopped\n",
				pid);
	}

	return diag;
}

static int rte_port_offload_setup(struct rte_port* port, struct rte_ethdev_configure* p_cfg)
{
	int ret;
	unsigned int i;
	port->dev_conf.txmode = p_cfg->tx_mode;
    port->dev_conf.rxmode = p_cfg->rx_mode;

	ret = eth_dev_info_get_print_err(p_cfg->port_id, &port->dev_info);
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
    if (p_cfg->eth_link_speed)
		port->dev_conf.link_speeds = p_cfg->eth_link_speed;
     if (p_cfg->max_rx_pkt_len)
		port->dev_conf.rxmode.mtu = p_cfg->max_rx_pkt_len -
			get_eth_overhead(&port->dev_info);
	/* set flag to initialize port/queue */
    port->need_reconfig = 1;
	port->need_reconfig_queues = 1;
	port->tx_metadata = 0;

	/*
	 * Check for maximum number of segments per MTU.
	 * Accordingly update the mbuf data size.
	 */
	if (port->dev_info.rx_desc_lim.nb_mtu_seg_max != UINT16_MAX &&
	    port->dev_info.rx_desc_lim.nb_mtu_seg_max != 0) {
		uint32_t eth_overhead = get_eth_overhead(&port->dev_info);
		uint16_t mtu;

		if (rte_eth_dev_get_mtu(p_cfg->port_id, &mtu) == 0) {
			uint16_t data_size = (mtu + eth_overhead) /
				port->dev_info.rx_desc_lim.nb_mtu_seg_max;
			uint16_t buffer_size = data_size + RTE_PKTMBUF_HEADROOM;

			if (buffer_size > p_cfg->mbp.mbuf_data_size[0]) {
				p_cfg->mbp.mbuf_data_size[0] = buffer_size;
				RT_ETHDEV_LOG(WARNING,
					"Configured mbuf size of the first segment %lu on port %d\n",
					p_cfg->mbp.mbuf_data_size[0], p_cfg->port_id);
			}
		}
	}

	for (i = 0; i < RTE_MAX_QUEUES_PER_PORT; ++i) {
		port->nb_rx_desc[i] = p_cfg->nb_rx_desc[i];
		port->nb_tx_desc[i] = p_cfg->nb_tx_desc[i];
	}

    return 0;
}

static int rte_port_ex_setup(struct rte_port* port, struct rte_ethdev_configure* p_cfg)
{
	int ret = 0;
	int i = 0;
	uint16_t pid = p_cfg->port_id;

	ret = eth_dev_info_get_print_err(pid, &port->dev_info);
	if (ret != 0)
		return ret;

	if (p_cfg->nb_rxq > 1) {
		port->dev_conf.rx_adv_conf.rss_conf.rss_key = NULL;
			port->dev_conf.rx_adv_conf.rss_conf.rss_hf =
				port->dev_info.flow_type_rss_offloads;
	} else {
		port->dev_conf.rx_adv_conf.rss_conf.rss_key = NULL;
		port->dev_conf.rx_adv_conf.rss_conf.rss_hf = 0;
	}

	if (port->dev_conf.rx_adv_conf.rss_conf.rss_hf != 0) {
		port->dev_conf.rxmode.mq_mode =
			(enum rte_eth_rx_mq_mode)
				(p_cfg->rx_mq_mode & RTE_ETH_MQ_RX_RSS);
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

static int rxtx_port_setup(struct rte_port* port, struct rte_ethdev_configure* p_cfg)
{
    uint16_t qid;
    uint64_t offloads;

    for (qid = 0; qid < p_cfg->nb_rxq; qid++) {
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
		if (p_cfg->rx_pthresh != RTE_PARAM_UNSET)
			port->rxq[qid].conf.rx_thresh.pthresh = p_cfg->rx_pthresh;

		if (p_cfg->rx_hthresh != RTE_PARAM_UNSET)
			port->rxq[qid].conf.rx_thresh.hthresh = p_cfg->rx_hthresh;

		if (p_cfg->rx_wthresh != RTE_PARAM_UNSET)
			port->rxq[qid].conf.rx_thresh.wthresh = p_cfg->rx_wthresh;

		if (p_cfg->rx_free_thresh != RTE_PARAM_UNSET)
			port->rxq[qid].conf.rx_free_thresh = p_cfg->rx_free_thresh;

		if (p_cfg->rx_drop_en != RTE_PARAM_UNSET)
			port->rxq[qid].conf.rx_drop_en = p_cfg->rx_drop_en;

		port->nb_rx_desc[qid] = p_cfg->nb_rxd;
    }

    for (qid = 0; qid < p_cfg->nb_txq; qid++) {
        offloads = port->txq[qid].conf.offloads;
		port->txq[qid].conf = port->dev_info.default_txconf;
		if (offloads != 0)
			port->txq[qid].conf.offloads = offloads;

		/* Check if any Tx parameters have been passed */
		if (p_cfg->tx_pthresh != RTE_PARAM_UNSET)
			port->txq[qid].conf.tx_thresh.pthresh = p_cfg->tx_pthresh;

		if (p_cfg->tx_hthresh != RTE_PARAM_UNSET)
			port->txq[qid].conf.tx_thresh.hthresh = p_cfg->tx_hthresh;

		if (p_cfg->tx_wthresh != RTE_PARAM_UNSET)
			port->txq[qid].conf.tx_thresh.wthresh = p_cfg->tx_wthresh;

		if (p_cfg->tx_rs_thresh != RTE_PARAM_UNSET)
			port->txq[qid].conf.tx_rs_thresh = p_cfg->tx_rs_thresh;

		if (p_cfg->tx_free_thresh != RTE_PARAM_UNSET)
			port->txq[qid].conf.tx_free_thresh = p_cfg->tx_free_thresh;

		port->nb_tx_desc[qid] = p_cfg->nb_txd; 
    }

	return 0;
}

static int rte_port_setup(struct rte_port* port, struct rte_ethdev_configure* p_cfg)
{
	int ret;
	if (p_cfg->kni_ifaces) {
		ret = rte_kni_init(p_cfg->kni_ifaces);
		if (ret != 0)
			return -1;
	}

	ret = rte_port_offload_setup(port, p_cfg);
	if (ret != 0)
		return -1;
	
	ret = rte_port_ex_setup(port, p_cfg);
	if (ret != 0)
		return -1;
	
	ret = rxtx_port_setup(port, p_cfg);
	if (ret != 0)
		return -1;

    return 0;
}

static struct rte_kni* kni_alloc(struct pss_port* ps_p, struct rte_ethdev_configure* p_cfg) {
	uint8_t i;
    struct rte_kni_conf conf;
    struct rte_kni *kni;
	struct rte_port *rtp = (struct rte_port*)ps_p->data;

	memset(&conf, 0, sizeof(conf));
    conf.group_id = p_cfg->port_id;
	if (p_cfg->ex_mbp)
    	conf.mbuf_size = p_cfg->mbp.mbuf_data_size[0];
    else 
		conf.mbuf_size = rte_gethdev_get_config()->gmbp.mbuf_data_size[0];
	snprintf(conf.name, sizeof(conf.name), "v%s", ps_p->name);
    kni = rte_kni_alloc(rtp->rxq[0].mbp, &conf, NULL);

	return kni;
}

int rte_eth_setup(struct pss_port* ps_p) {
	struct rte_port* rt_p = (struct rte_port*)ps_p->data;
	uint16_t portid = ps_p->port_id;
	struct rte_ethdev_configure* p_cfg = rte_eth_get_config(portid);
	int ret;

	if (rt_p->port_status == RTE_PORT_STARTED || rt_p->port_status == RTE_PORT_HANDLING) {
		RT_ETHDEV_LOG(WARNING, 
			"Port id %d is still on started status\n", portid);
		return -1;
	}

	ret = rte_eth_load_config(ps_p->name, portid);
	if (ret != 0) {
		RT_ETHDEV_LOG(WARNING, 
			"Port id %d cfg load failed\n", portid);
		return -1;
	}

	ret = rte_port_setup(rt_p, p_cfg);
	if (ret != 0)
		return ret;

	ret = rte_port_start(portid, rt_p);
	if (ret != 0)
		return ret;
	
	if (p_cfg->promiscuous_enable) {
		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0) {
			RT_ETHDEV_LOG(WARNING,
				"Error during enabling promiscuous mode for port %u: %s - ignore\n",
				portid, rte_strerror(-ret));
			goto failed;
		}
	}

	if (rt_p->kni_enable) {
		rt_p->kni = kni_alloc(ps_p, p_cfg);
		if (rt_p->kni == NULL)
			goto failed;
	}

	ps_p->ops.pkt_alloc = rte_rxtx_alloc;
	ps_p->ops.pkt_free = rte_rxtx_free;
	ps_p->ops.pkt_rx_burst = rte_rx_burst;
	ps_p->ops.pkt_tx_burst = rte_tx_burst;

	return 0;
failed:
	rte_port_stop(portid, rt_p);
	return -1;
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

int rte_port_stop(uint16_t pid, struct rte_port* port)
{
	int ret;

	if (port->port_status == RTE_PORT_STOPPED || port->port_status == RTE_PORT_CLOSED)
		return 0;

	if (port->port_status == RTE_PORT_STARTED)
		port->port_status = RTE_PORT_HANDLING;
	
	if (port->kni_enable && port->kni) {
		ret = rte_kni_release(port->kni);
		if (ret != 0) {
			RT_ETHDEV_LOG(ERR, "release kni failed for port %u\n",
				pid);
			port->port_status == RTE_PORT_STARTED;
			return -1;
		}
	}

	ret = eth_dev_stop_mp(pid);
	if (ret != 0) {
		RT_ETHDEV_LOG(ERR, "stop failed for port %u\n",
			pid);
		port->port_status == RTE_PORT_STARTED;
		return -1;
	}

	if (port->port_status == RTE_PORT_HANDLING)
		port->port_status = RTE_PORT_STOPPED;

	return 0;
}

int rte_port_close(uint16_t pid, struct rte_port* port)
{
	int ret;

	if (port->port_status == RTE_PORT_CLOSED)
		return 0;
	
	ret = rte_eth_dev_close(pid);

	return ret;
}