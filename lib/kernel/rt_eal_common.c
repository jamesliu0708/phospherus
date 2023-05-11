#include <rt_eal_common.h>
#include <rte_mempool.h>

struct rte_mempool* rt_mbuf_pool_create(const char* name, 
                        uint8_t mp_alloc_type,
                        unsigned int mempool_cache,
                        uint16_t mbuf_size, unsigned nb_mbuf, 
                        unsigned int socket_id)
{
    struct rte_mempool *rte_mp = NULL;
    uint32_t mb_size;

    mb_size = sizeof(struct rte_mbuf) + mbuf_size;
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
				mbuf_size, (unsigned int) mb_mempool_cache,
				sizeof(struct rte_pktmbuf_pool_private),
				socket_id, mempool_flags);
			if (rte_mp == NULL)
				goto err;

			if (rte_mempool_populate_anon(rte_mp) == 0) {
				rte_mempool_free(rte_mp);
				rte_mp = NULL;
				goto err;
			}
			rte_pktmbuf_pool_init(rte_mp, NULL);
			rte_mempool_obj_iter(rte_mp, rte_pktmbuf_init, NULL);
			rte_mempool_mem_iter(rte_mp, dma_map_cb, NULL);
			break;
        }
    case MP_ALLOC_XMEM:
	case MP_ALLOC_XMEM_HUGE:
		{
			int heap_socket;
			bool huge = mp_alloc_type == MP_ALLOC_XMEM_HUGE;

			if (setup_extmem(nb_mbuf, mbuf_seg_size, huge) < 0)
				rte_exit(EXIT_FAILURE, "Could not create external memory\n");

			heap_socket =
				rte_malloc_heap_get_socket(EXTMEM_HEAP_NAME);
			if (heap_socket < 0)
				rte_exit(EXIT_FAILURE, "Could not get external memory socket ID\n");

			TESTPMD_LOG(INFO, "preferred mempool ops selected: %s\n",
					rte_mbuf_best_mempool_ops());
			rte_mp = rte_pktmbuf_pool_create(pool_name, nb_mbuf,
					mb_mempool_cache, 0, mbuf_seg_size,
					heap_socket);
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
					(pool_name, nb_mbuf, mb_mempool_cache,
					 0, mbuf_seg_size, socket_id,
					 ext_mem, ext_num);
			free(ext_mem);
			break;
		}
    default:
        return NULL;
    }

    return rte_mp;
}