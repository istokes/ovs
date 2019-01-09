/*
 * Copyright (c) 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_errno.h>
#include "dp-packet.h"
#include "ovstest.h"
#include "dpdk.h"
#include "smap.h"
#include "csum.h"
#include "crc32c.h"

#define N_MBUFS 1024
#define MBUF_DATA_LEN 2048

static int num_tests = 0;

/* Global var to hold a mempool instance, "test-mp", used in all of the tests
 * below. This instance is instantiated in dpdk_setup_eal_with_mp(). */
static struct rte_mempool *mp;

/* Test data used to fill the packets with data. Note that this isn't a string
 * that repsents a valid packet, by any means. The pattern is generated in set_
 * testing_pattern_str() and the sole purpose is to verify the data remains the
 * same after inserting and operating on multi-segment mbufs. */
static char *test_str;

/* Asserts a dp_packet that holds a single mbuf, where:
 * - nb_segs must be 1;
 * - pkt_len must be equal to data_len which in turn must equal the provided
 *   'pkt_len';
 * - data_off must start at the provided 'data_ofs';
 * - next must be NULL. */
static void
assert_single_mbuf(struct dp_packet *pkt, uint16_t data_ofs,
                   uint32_t pkt_len) {
    struct rte_mbuf *mbuf = CONST_CAST(struct rte_mbuf *, &pkt->mbuf);
    ovs_assert(mbuf->nb_segs == 1);
    ovs_assert(mbuf->data_off == data_ofs);
    ovs_assert(mbuf->pkt_len == mbuf->data_len);
    ovs_assert(mbuf->pkt_len == pkt_len);
    ovs_assert(mbuf->next == NULL);
}

/* Asserts a dp_packet that holds multiple mbufs, where:
 * - nb_segs must be > 1 and equal to the provided 'nb_segs';
 * - data_off must start at the provided 'data_ofs';
 * - pkt_len must be equal to the provided 'pkt_len' and the some of each
 *   mbufs' 'data_len' must equal the pky_len;
 * - next must not be NULL. */
static void
assert_multiple_mbufs(struct dp_packet *pkt, uint16_t data_ofs,
                      uint32_t pkt_len, uint16_t nb_segs) {
    struct rte_mbuf *mbuf = CONST_CAST(struct rte_mbuf *, &pkt->mbuf);
    ovs_assert(mbuf->nb_segs > 1 && mbuf->nb_segs == nb_segs);
    ovs_assert(mbuf->data_off == data_ofs);
    ovs_assert(mbuf->pkt_len != mbuf->data_len);
    ovs_assert(mbuf->next != NULL);
    ovs_assert(mbuf->pkt_len == pkt_len);
    /* Make sure pkt_len equals the sum of all segments data_len */
    while (mbuf) {
        pkt_len -= rte_pktmbuf_data_len(mbuf);
        mbuf = mbuf->next;
    }
    ovs_assert(pkt_len == 0);
}

/* Asserts that the data existing in a packet, starting at 'data_ofs' of the
 * first mbuf and of length 'data_len' matches the global test_str used,
 * starting at index 0 and of the same length. */
static void
assert_data(struct dp_packet *pkt, uint16_t data_ofs, uint16_t data_len) {
    struct rte_mbuf *mbuf = CONST_CAST(struct rte_mbuf *, &pkt->mbuf);

    char *data = xmalloc(sizeof(*data) * data_len);
    const char *rd = rte_pktmbuf_read(mbuf, data_ofs, data_len, data);

    ovs_assert(rd != NULL);
    ovs_assert(memcmp(rd, test_str, data_len) == 0);

    free(data);
}

static void
set_testing_pattern_str(void) {
    static const char *pattern = "1234567890";

    /* Pattern will be of size 5000B */
    size_t test_str_len = 5000;
    test_str = xmalloc(test_str_len * sizeof(*test_str) + 1);

    for (int i = 0; i < test_str_len; i += strlen(pattern)) {
        memcpy(test_str + i, pattern, strlen(pattern));
    }

    test_str[test_str_len] = 0;
}

static void
dpdk_eal_init(void) {
    struct smap other_config;
    smap_init(&other_config);

    printf("Initialising EAL...\n");
    smap_add(&other_config, "dpdk-init", "true");
    smap_add(&other_config, "dpdk-lcore-mask", "10");
    smap_add(&other_config, "dpdk-socket-mem", "2048,0");
    smap_add(&other_config, "dpdk-multi-seg-mbufs", "true");

    dpdk_init(&other_config);
}

/* The allocation of mbufs here mimics the logic in dpdk_mp_create in
 * netdev-dpdk.c. */
static struct rte_mempool *
dpdk_mp_create(char *mp_name) {
    uint16_t mbuf_size, aligned_mbuf_size, mbuf_priv_data_len;

    mbuf_size = sizeof (struct dp_packet) +
                            MBUF_DATA_LEN + RTE_PKTMBUF_HEADROOM;
    aligned_mbuf_size = ROUND_UP(mbuf_size, RTE_CACHE_LINE_SIZE);
    mbuf_priv_data_len = sizeof(struct dp_packet) - sizeof(struct rte_mbuf) +
                         (aligned_mbuf_size - mbuf_size);

    struct rte_mempool *mpool = rte_pktmbuf_pool_create(
                                    mp_name, N_MBUFS,
                                    RTE_MEMPOOL_CACHE_MAX_SIZE,
                                    mbuf_priv_data_len,
                                    MBUF_DATA_LEN +
                                    RTE_PKTMBUF_HEADROOM /* defaults 128B */,
                                    SOCKET_ID_ANY);
    if (mpool) {
        printf("Allocated \"%s\" mempool with %u mbufs\n", mp_name, N_MBUFS);
    } else {
        printf("Failed mempool \"%s\" create request of %u mbufs: %s.\n",
               mp_name, N_MBUFS, rte_strerror(rte_errno));

        ovs_assert(mpool != NULL);
    }

    return mpool;
}

static void
dpdk_setup_eal_with_mp(void) {
    dpdk_eal_init();

    mp = dpdk_mp_create("test-mp");
    ovs_assert(mp != NULL);
}

static struct dp_packet *
dpdk_mp_alloc_pkt(struct rte_mempool *mpool) {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mpool);

    struct dp_packet *pkt = (struct dp_packet *) mbuf;
    pkt->source = DPBUF_DPDK;

    return pkt;
}

/* Similar to dp_packet_put() in dp-packet.c, appends the 'size' bytes of data
 * in 'p' to the tail end of 'pkt', allocating new mbufs if needed. */
static struct dp_packet *
dpdk_pkt_put(struct dp_packet *pkt, void *p, size_t size) {
    uint16_t max_data_len, nb_segs;
    struct rte_mbuf *mbuf, *fmbuf;

    mbuf = CONST_CAST(struct rte_mbuf *, &pkt->mbuf);

    /* All new allocated mbuf's max data len is the same */
    max_data_len = mbuf->buf_len - mbuf->data_off;

    /* Calculate # of needed mbufs to accomodate 'miss_len' */
    nb_segs = size / max_data_len;
    if (size % max_data_len) {
        nb_segs += 1;
    }

    /* Proceed with the allocation of new mbufs */
    mp = mbuf->pool;
    fmbuf = mbuf;
    mbuf = rte_pktmbuf_lastseg(mbuf);

    for (int i = 0; i < nb_segs; i++) {
        /* This takes care of initialising buf_len, data_len and other
         * fields properly */
        mbuf->next = rte_pktmbuf_alloc(mp);
        if (!mbuf->next) {
            printf("Problem allocating more mbufs for tests.\n");
            rte_pktmbuf_free(mbuf);
            fmbuf = NULL;
            return NULL;
        }

        fmbuf->nb_segs += 1;

        mbuf = mbuf->next;
    }

    dp_packet_mbuf_write(fmbuf, 0, size, p);

    dp_packet_set_size(pkt, size);

    return pkt;
}

static int
test_dpdk_packet_insert_headroom(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Reserve 256B of header */
    size_t str_len = 512;
    dp_packet_reserve(pkt, str_len);
    char *p = dp_packet_push_uninit(pkt, str_len);
    ovs_assert(p != NULL);
    /* Put the first 512B of "test_str" in the allocated header */
    memcpy(p, test_str, str_len);

    /* Check properties and data are as expected */
    assert_single_mbuf(pkt, RTE_PKTMBUF_HEADROOM, str_len);
    assert_data(pkt, 0, str_len);

    dp_packet_uninit(pkt);

    return 0;
}

static int
test_dpdk_packet_insert_tailroom_and_headroom(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Reserve 256B of header */
    size_t head_len = 256;
    dp_packet_reserve(pkt, head_len);

    /* Put the first 512B of "test_str" in the packet's header */
    size_t str_len = 512;
    char *p = dp_packet_put(pkt, test_str, str_len);
    ovs_assert(p != NULL);

    /* Fill the reserved 256B of header */
    p = dp_packet_push_uninit(pkt, head_len);
    ovs_assert(p != NULL);

    /* Check properties and data are as expected */
    assert_single_mbuf(pkt, RTE_PKTMBUF_HEADROOM, str_len + head_len);

    /* Check the data inserted in the packet is correct */
    char *data = xmalloc(sizeof(*data) * (str_len + head_len));
    const char *rd = rte_pktmbuf_read(&pkt->mbuf, 0, str_len + head_len, data);
    ovs_assert(rd != NULL);
    /* Because of the headroom inserted, the data now begin at offset 256 */
    ovs_assert(memcmp(rd + head_len, test_str, str_len) == 0);

    dp_packet_uninit(pkt);
    free(data);

    return 0;
}

static int
test_dpdk_packet_insert_tailroom_and_headroom_multiple_mbufs(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Put the first 2050B of "test_str" in the packet, just enought to
     * allocate two mbufs */
    size_t str_len = MBUF_DATA_LEN + 2;
    pkt = dpdk_pkt_put(pkt, test_str, str_len);
    ovs_assert(pkt != NULL);

    /* Put the first 512B of "test_str" in the packet's header */
    size_t tail_len = 512;
    char *p = dp_packet_put(pkt, test_str, tail_len);
    ovs_assert(p != NULL);

    /* Fill the entire headroom */
    size_t head_len = RTE_PKTMBUF_HEADROOM;
    p = dp_packet_push_uninit(pkt, head_len);
    ovs_assert(p != NULL);
    /* Copy the data to the reserved headroom */
    memcpy(p, test_str, head_len);

    /* Check properties and data are as expected */
    size_t pkt_len = head_len + str_len + tail_len;
    uint16_t nb_segs = 2;
    assert_multiple_mbufs(pkt, 0, pkt_len, nb_segs);

    /* Check the data inserted in the packet is correct */
    char *data = xmalloc(sizeof(*data) * pkt_len);
    const char *rd = rte_pktmbuf_read(&pkt->mbuf, 0, pkt_len, data);
    ovs_assert(rd != NULL);
    ovs_assert(memcmp(rd, test_str, head_len) == 0);
    ovs_assert(memcmp(rd + head_len + str_len, test_str, tail_len) == 0);

    dp_packet_uninit(pkt);
    free(data);

    return 0;
}

static int
test_dpdk_packet_insert_tailroom_multiple_mbufs(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Put the first 2050B of "test_str" in the packet, just enought to
     * allocate two mbufs */
    size_t str_len = MBUF_DATA_LEN + 2;
    pkt = dpdk_pkt_put(pkt, test_str, str_len);
    ovs_assert(pkt != NULL);

    /* Put the first 2000B of "test_str" in the packet's end */
    size_t tail_len = 2000;
    char *p = dp_packet_put(pkt, test_str, tail_len);
    ovs_assert(p != NULL);

    /* Check properties and data are as expected */
    char *data = xmalloc(sizeof(*data) * (str_len + tail_len));
    const char *rd = rte_pktmbuf_read(&pkt->mbuf, 0, str_len + tail_len, data);
    ovs_assert(rd != NULL);
    /* Because of the headroom inserted, the data now begin at offset 256 */
    ovs_assert(memcmp(rd + str_len, test_str, tail_len) == 0);

    dp_packet_uninit(pkt);
    free(data);

    return 0;
}

static int
test_dpdk_packet_insert_headroom_multiple_mbufs(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Put the first 2050B of "test_str" in the packet, just enought to
     * allocate two mbufs */
    size_t str_len = MBUF_DATA_LEN + 2;
    pkt = dpdk_pkt_put(pkt, test_str, str_len);

    /* Fill the entire headroom */
    size_t head_len = RTE_PKTMBUF_HEADROOM;
    char *p = dp_packet_push_uninit(pkt, head_len);
    ovs_assert(p != NULL);

    /* Check properties and data are as expected */
    char *data = xmalloc(sizeof(*data) * (str_len + head_len));
    const char *rd = rte_pktmbuf_read(&pkt->mbuf, 0, str_len + head_len, data);
    ovs_assert(rd != NULL);
    /* Because of the headroom inserted, the data is at offset 'head_len' */
    ovs_assert(memcmp(rd + head_len, test_str, str_len) == 0);

    dp_packet_uninit(pkt);
    free(data);

    return 0;
}

static int
test_dpdk_packet_change_size(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Put enough data in the packet that spans three mbufs (5120B) */
    size_t str_len = MBUF_DATA_LEN * 2 + 1024;
    pkt = dpdk_pkt_put(pkt, test_str, str_len);
    ovs_assert(pkt != NULL);

    /* Check properties and data are as expected */
    uint16_t nb_segs = 3;
    assert_multiple_mbufs(pkt, RTE_PKTMBUF_HEADROOM, str_len, nb_segs);

    /* Change the size of the packet to fit in a single mbuf */
    dp_packet_clear(pkt);

    assert_single_mbuf(pkt, RTE_PKTMBUF_HEADROOM, 0);

    dp_packet_uninit(pkt);

    return 0;
}

/* Shift() tests */

static int
test_dpdk_packet_shift_single_mbuf(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Put the first 1024B of "test_str" in the packet */
    size_t str_len = 1024;
    char *p = dp_packet_put(pkt, test_str, str_len);
    ovs_assert(p != NULL);

    /* Shift data right by 512B */
    uint16_t shift_len = 512;
    dp_packet_shift(pkt, shift_len);

    /* Check properties and data are as expected */
    assert_single_mbuf(pkt, RTE_PKTMBUF_HEADROOM + shift_len, str_len);
    assert_data(pkt, 0, str_len);

    dp_packet_uninit(pkt);

    return 0;
}

static int
test_dpdk_packet_shift_multiple_mbufs(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Put the data in "test_str" in the packet */
    size_t str_len = strlen(test_str);
    pkt = dpdk_pkt_put(pkt, test_str, str_len);
    ovs_assert(pkt != NULL);

    /* Check properties and data are as expected */
    uint16_t nb_segs = 3;
    assert_multiple_mbufs(pkt, RTE_PKTMBUF_HEADROOM, str_len, nb_segs);

    /* Shift data right by 1024B */
    uint16_t shift_len = 1024;
    dp_packet_shift(pkt, shift_len);

    /* Check the data has been inserted correctly */
    assert_multiple_mbufs(pkt, RTE_PKTMBUF_HEADROOM + shift_len, str_len,
                          nb_segs);
    assert_data(pkt, 0, str_len);

    dp_packet_uninit(pkt);

    return 0;
}

static int
test_dpdk_packet_shift_right_then_left(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Put the first 1024B of "test_str" in the packet */
    size_t str_len = strlen(test_str);
    pkt = dpdk_pkt_put(pkt, test_str, str_len);
    ovs_assert(pkt != NULL);

    /* Shift data right by 1024B */
    int16_t shift_len = 1024;
    dp_packet_shift(pkt, 1024);

    /* Check properties and data are as expected */
    uint16_t nb_segs = 3;
    assert_multiple_mbufs(pkt, RTE_PKTMBUF_HEADROOM + shift_len, str_len,
                          nb_segs);

    /* Shift data left by 512B */
    dp_packet_shift(pkt, -shift_len);

    /* We negative shift_len (-shift_len) since  */
    assert_multiple_mbufs(pkt, RTE_PKTMBUF_HEADROOM, str_len,
                          nb_segs);
    assert_data(pkt, 0, str_len);

    dp_packet_uninit(pkt);

    return 0;
}

static int
test_dpdk_packet_equal_multiple_mbufs(void) {
    /* Allocate first packet for comparison */
    struct dp_packet *pkt1 = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt1 != NULL);

    /* Put the data in "test_str" in the packet */
    size_t str_len = strlen(test_str);
    pkt1 = dpdk_pkt_put(pkt1, test_str, str_len);
    ovs_assert(pkt1 != NULL);

    /* Check properties and data are as expected */
    uint16_t nb_segs = 3;
    assert_multiple_mbufs(pkt1, RTE_PKTMBUF_HEADROOM, str_len, nb_segs);

    /* Allocate second packet for comparison */
    struct dp_packet *pkt2 = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt2 != NULL);

    /* Put the data in "test_str" in the packet */
    pkt2 = dpdk_pkt_put(pkt2, test_str, str_len);
    ovs_assert(pkt2 != NULL);

    /* Check properties and data are as expected */
    assert_multiple_mbufs(pkt2, RTE_PKTMBUF_HEADROOM, str_len, nb_segs);

    ovs_assert(dp_packet_equal(pkt1, pkt2));

    dp_packet_uninit(pkt1);
    dp_packet_uninit(pkt2);

    return 0;
}

static int
test_dpdk_packet_single_mbuf_to_linear_malloc(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Put the first 1024B of "test_str" in the packet */
    size_t str_len = 1024;
    char *p = dp_packet_put(pkt, test_str, str_len);
    ovs_assert(p != NULL);

    char *paddr = rte_pktmbuf_mtod(&pkt->mbuf, char *);
    /* Convert DPBUF_DPDK packet in a linear DPBUF_MALLOC packet */
    if (!dp_packet_is_linear(pkt)) {
        dp_packet_linearize(pkt);
    }

    char *d = dp_packet_data(pkt);

    /* Check properties and data are as expected, namely:
     * - The packet is still a DPBUF_DPDK packet;
     * - The returned address is still an address in the mbuf;
     * - Single mbuf properties still hold. */
    ovs_assert(d != NULL);
    ovs_assert(pkt->source == DPBUF_DPDK);
    ovs_assert(d == paddr);
    assert_single_mbuf(pkt, RTE_PKTMBUF_HEADROOM, str_len);

    dp_packet_uninit(pkt);

    return 0;
}

static int
test_dpdk_packet_multiple_mbufs_to_linear_malloc(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Put the data in "test_str" in the packet */
    size_t str_len = strlen(test_str);
    pkt = dpdk_pkt_put(pkt, test_str, str_len);
    ovs_assert(pkt != NULL);

    /* Check properties and data are as expected */
    uint16_t nb_segs = 3;
    assert_multiple_mbufs(pkt, RTE_PKTMBUF_HEADROOM, str_len, nb_segs);

    char *paddr = rte_pktmbuf_mtod(&pkt->mbuf, char *);
    /* Convert DPBUF_DPDK packet in a linear DPBUF_MALLOC packet */
    if (!dp_packet_is_linear(pkt)) {
        dp_packet_linearize(pkt);
    }

    char *d = dp_packet_data(pkt);

    /* Check properties and data are as expected, namely:
     * - The packet is now a DPBUF_MALLOC packet;
     * - The returned address is a new address;
     * - All expected data is now in the new address. */
    ovs_assert(d != NULL);
    ovs_assert(pkt->source == DPBUF_MALLOC);
    ovs_assert(d != paddr);
    ovs_assert(memcmp(d, test_str, str_len) == 0);

    dp_packet_uninit(pkt);

    return 0;
}

static int
test_dpdk_packet_single_mbuf_csum(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Put the first 1023B of "test_str" in the packet. Note that 1023B is an
     * odd number to cover for this case for the csum */
    size_t str_len = 1023;
    char *p = dp_packet_put(pkt, test_str, str_len);
    ovs_assert(p != NULL);

    /* Calculate the checksum on the whole packet's data */
    uint32_t pkt_csum = packet_csum(pkt, 0, dp_packet_size(pkt));

    uint32_t data_csum = csum(dp_packet_data(pkt), dp_packet_size(pkt));

    /* Check the checksums are the same */
    ovs_assert(pkt_csum == data_csum);
    assert_single_mbuf(pkt, RTE_PKTMBUF_HEADROOM, str_len);

    dp_packet_uninit(pkt);

    return 0;
}

static int
test_dpdk_packet_multiple_mbufs_csum(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Put the data in "test_str" in the packet */
    size_t str_len = strlen(test_str);
    pkt = dpdk_pkt_put(pkt, test_str, str_len);
    ovs_assert(pkt != NULL);

    /* Check properties and data are as expected */
    uint16_t nb_segs = 3;
    assert_multiple_mbufs(pkt, RTE_PKTMBUF_HEADROOM, str_len, nb_segs);

    /* Calculate the checksum on the whole packet's data */
    uint32_t pkt_csum = packet_csum(pkt, 0, dp_packet_size(pkt));

    char *data = xmalloc(dp_packet_size(pkt));
    rte_pktmbuf_read(&pkt->mbuf, 0, dp_packet_size(pkt), data);
    uint32_t data_csum = csum(data, dp_packet_size(pkt));

    /* Check the checksums are the same */
    ovs_assert(pkt_csum == data_csum);
    ovs_assert(memcmp(data, test_str, str_len) == 0);

    free(data);
    dp_packet_uninit(pkt);

    return 0;
}

static int
test_dpdk_packet_multiple_mbufs_crc32c(void) {
    struct dp_packet *pkt = dpdk_mp_alloc_pkt(mp);
    ovs_assert(pkt != NULL);

    /* Put the data in "test_str" in the packet */
    size_t str_len = strlen(test_str);
    pkt = dpdk_pkt_put(pkt, test_str, str_len);
    ovs_assert(pkt != NULL);

    /* Check properties and data are as expected */
    uint16_t nb_segs = 3;
    assert_multiple_mbufs(pkt, RTE_PKTMBUF_HEADROOM, str_len, nb_segs);

    /* Calculate the crc32 on the whole packet's data */
    uint32_t pkt_crc32 = packet_crc32c(pkt, 0, dp_packet_size(pkt));

    char *data = xmalloc(dp_packet_size(pkt));
    rte_pktmbuf_read(&pkt->mbuf, 0, dp_packet_size(pkt), data);
    uint32_t data_crc32 = crc32c((uint8_t *) data, dp_packet_size(pkt));

    /* Check the crc32 results are the same */
    ovs_assert(pkt_crc32 == data_crc32);
    ovs_assert(memcmp(data, test_str, str_len) == 0);

    free(data);
    dp_packet_uninit(pkt);

    return 0;
}

static int
test_dpdk_packet(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    /* Setup environment for tests */
    dpdk_setup_eal_with_mp();
    set_testing_pattern_str();

    test_dpdk_packet_insert_headroom();
    num_tests++;
    test_dpdk_packet_insert_tailroom_and_headroom();
    num_tests++;
    test_dpdk_packet_insert_tailroom_multiple_mbufs();
    num_tests++;
    test_dpdk_packet_insert_headroom_multiple_mbufs();
    num_tests++;
    test_dpdk_packet_insert_tailroom_and_headroom_multiple_mbufs();
    num_tests++;
    test_dpdk_packet_change_size();
    num_tests++;
    test_dpdk_packet_shift_single_mbuf();
    num_tests++;
    test_dpdk_packet_shift_multiple_mbufs();
    num_tests++;
    test_dpdk_packet_shift_right_then_left();
    num_tests++;
    test_dpdk_packet_equal_multiple_mbufs();
    num_tests++;
    test_dpdk_packet_single_mbuf_to_linear_malloc();
    num_tests++;
    test_dpdk_packet_multiple_mbufs_to_linear_malloc();
    num_tests++;
    test_dpdk_packet_single_mbuf_csum();
    num_tests++;
    test_dpdk_packet_multiple_mbufs_csum();
    num_tests++;
    test_dpdk_packet_multiple_mbufs_crc32c();
    num_tests++;

    printf("Executed %d tests\n", num_tests);

    exit(0);
}

OVSTEST_REGISTER("test-dpdk-packet", test_dpdk_packet);
