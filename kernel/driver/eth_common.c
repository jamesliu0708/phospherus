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
#include <numa.h>
#include <sys/mman.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <driver/rt_ethdev.h>

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