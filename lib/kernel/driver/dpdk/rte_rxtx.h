#ifndef _RTE_RXTX_H
#define _RTE_RXTX_H
#include <rte_common.h>
#include <rte_ethdev.h>
#include <pss_port.h>
#include <rte_mbuf.h>
#include "rte_eth.h"
#include "rte_eth_config.h"
#include "rte_eth_core.h"

__rte_always_inline uint16_t rte_rx_burst(struct pss_port* pp, 
                            uint16_t queue_id, struct pss_pktbuf** pkt, 
                            const unsigned int nb_pkts)
{
	struct rte_mbuf *rx_pkts[nb_pkts];
	uint16_t ret;
	unsigned int i;

	ret = rte_eth_rx_burst(pp->port_id, queue_id, rx_pkts, nb_pkts);
	for (i = 0; i < ret; ++i) {
		pkt[i]->payload = rte_pktmbuf_mtod(rx_pkts[i], void*);
		pkt[i]->pktlen = rx_pkts[i]->pkt_len;
		pkt[i]->pbuf = rx_pkts[i];
	}

	return ret;
}

__rte_always_inline uint16_t rte_tx_burst(struct pss_port* pp,
                            uint16_t queue_id, struct pss_pktbuf** pkt,
                            const unsigned int nb_pkts)
{
	struct rte_mbuf *tx_pkts[nb_pkts];
	unsigned int i;

	for (i = 0; i < nb_pkts; ++i) {
		tx_pkts[i] = (struct rte_mbuf*)pkt[i]->pbuf;
	}

	return rte_eth_tx_burst(pp->port_id, queue_id, tx_pkts, nb_pkts);
}

__rte_always_inline uint16_t rte_rxtx_alloc(struct pss_port* pp,
                            uint16_t queue_id, struct pss_pktbuf** pkt,
                            const unsigned int nb_pkts, void* flag)
{
	struct rte_port* rp = (struct rte_port*)pp->data;
	struct rte_mbuf* rtebufs[nb_pkts];
	int ret;
	unsigned int i;
	int rxtx_f = *(int*)flag;

	struct rte_mempool* mbp = rxtx_f? rp->rxq[queue_id].mbp: rp->txq[queue_id].mbp;
	ret = rte_pktmbuf_alloc_bulk(mbp, rtebufs, nb_pkts);
	for (i = 0; i < nb_pkts; ++i) {
		pkt[i]->payload = rte_pktmbuf_mtod(rtebufs[i], void*);
		pkt[i]->pktlen = rtebufs[i]->pkt_len;
		pkt[i]->pbuf = rtebufs[i];
	}

	return ret;
}

__rte_always_inline void rte_rxtx_free(struct pss_port* pp,
                            uint16_t queue_id, struct pss_pktbuf** pkt,
                            const unsigned int nb_pkts, void* flag)
{
	struct rte_port* rp = (struct rte_port*)pp->data;
	struct rte_mbuf* rtebufs[nb_pkts];
	unsigned int i;
	int rxtx_f = *(int*)flag;

	struct rte_mempool* mbp = rxtx_f? rp->rxq[queue_id].mbp: rp->txq[queue_id].mbp;
	for (i = 0; i < nb_pkts; ++i) {
		rtebufs[i] = (struct rte_mbuf*)pkt[i]->pbuf;
	}

	rte_pktmbuf_free_bulk(rtebufs, nb_pkts);
}
#endif // _RTE_RXTX_H