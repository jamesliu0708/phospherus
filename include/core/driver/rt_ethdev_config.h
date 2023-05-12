#ifndef _RTE_ETHDEV_CONFIG_H
#define _RTE_ETHDEV_CONFIG_H

#define RSS_HASH_KEY_LENGTH 64

#define DEFAULT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE

#define RTE_MAX_SEGS_PER_PKT 255

#define MBUF_POOL_NAME_PFX "mb_pool"

#define RX_DESC_MAX 2048

#define TX_DESC_MAX 2048

#define MAX_PKT_BURST 512

#define DEF_MBUF_CACHE 250

#define MIN_TOTAL_NUM_MBUFS 1024

#define MAX_MEMPOOL 8

#define MAX_SEGS_BUFFER_SPLIT 8

#define RX_DESC_DEFAULT 1024

#define RX_DESC_MAX 2048

#define TX_DESC_MAX 2048

#define MAX_PKT_BURST 512

#define RSS_TYPES_CHAR_NUM_PER_LINE 64

#define DEF_MBUF_CACHE 250
#include <driver/rt_ethdev_generic.h>
#endif