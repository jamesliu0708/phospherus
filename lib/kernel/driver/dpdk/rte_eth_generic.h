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
#ifndef _RT_ETHDEV_GENERIC_H
#define _RT_ETHDEV_GENERIC_H
#include <stdint.h>

/*
 * It is used to allocate the memory for hash key.
 * The hash key size is NIC dependent.
 */
#ifndef RSS_HASH_KEY_LENGTH
#define RSS_HASH_KEY_LENGTH 64
#endif // RSS_HASH_KEY_LENGTH 64

/*
 * Default size of the mbuf data buffer to receive standard 1518-byte
 * Ethernet frames in a mono-segment memory buffer.
 */
#ifndef DEFAULT_MBUF_DATA_SIZE
#define DEFAULT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#endif // RTE_MBUF_DEFAULT_BUF_SIZE
/**< Default size of mbuf data buffer. */

/*
 * The maximum number of segments per packet is used when creating
 * scattered transmit packets composed of a list of mbufs.
 */
#ifndef RTE_MAX_SEGS_PER_PKT
#define RTE_MAX_SEGS_PER_PKT 255 /**< nb_segs is a 8-bit unsigned char. */
#endif // RTE_MAX_SEGS_PER_PKT

/* The prefix of the mbuf pool names created by the application. */
#define MBUF_POOL_NAME_PFX "mb_pool"

#define RTE_ETHERNET_DIR "/dev/shm"
#define RTE_ETHERDEV_ENV_NAME "eth-gconf"

#ifndef RX_DESC_MAX
#define RX_DESC_MAX    2048
#endif // RX_DESC_MAX
#ifndef TX_DESC_MAX
#define TX_DESC_MAX    2048
#endif // TX_DESC_MAX

#ifndef MAX_PKT_BURST
#define MAX_PKT_BURST 512
#endif // MAX_PKT_BURST

#ifndef DEF_PKT_BURST
#define DEF_PKT_BURST 32
#endif // DEF_PKT_BURST

#ifndef DEF_MBUF_CACHE
#define DEF_MBUF_CACHE 250
#endif // DEF_MBUF_CACHE

#ifndef MIN_TOTAL_NUM_BUFS
#define MIN_TOTAL_NUM_MBUFS 1024
#endif // MIN_TOTAL_NUM_BUFS

/* Maximum number of pools supported per Rx queue */
#ifndef MAX_MEMPOOL
#define MAX_MEMPOOL 8
#endif // MAX_MEMPOOL

/*
 * The maximum number of segments per packet is used to configure
 * buffer split feature, also specifies the maximum amount of
 * optional Rx pools to allocate mbufs to split.
 */
#ifndef MAX_SEGS_BUFFER_SPLIT
#define MAX_SEGS_BUFFER_SPLIT 8 /**< nb_segs is a 8-bit unsigned char. */
#endif // MAX_SEGS_BUFFER_SPLIT

/*
 * Configurable number of RX/TX ring descriptors.
 * Defaults are supplied by drivers via ethdev.
 */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024

#ifndef RX_DESC_MAX
#define RX_DESC_MAX    2048
#endif // RX_DESC_MAX
#ifndef TX_DESC_MAX
#define TX_DESC_MAX    2048
#endif

#ifndef MAX_PKT_BURST
#define MAX_PKT_BURST 512
#endif // MAX_PKT_BURST

#ifndef RSS_TYPES_CHAR_NUM_PER_LINE
#define RSS_TYPES_CHAR_NUM_PER_LINE 64
#endif // RSS_TYPES_CHAR_NUM_PER_LINE

#ifndef DEF_MBUF_CACHE
#define DEF_MBUF_CACHE 250
#endif // DEF_MBUF_CACHE

#endif // _RT_ETHDEV_GENERIC_H