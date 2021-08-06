/*
 * Copyright (c) 2021 Intel Corporation.
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

#ifndef DPIF_NETDEV_PRIVATE_DEFER_H
#define DPIF_NETDEV_PRIVATE_DEFER_H 1

#include <stdbool.h>
#include <stdint.h>

#include "dpif.h"
#include "dpif-netdev-perf.h"
#include "cmap.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Function definition for deferred work. */
typedef int (*dp_defer_work_func)(struct netdev *netdev, int qid, bool force);

/* Structure to track outstanding work to be done. */
struct dp_defer_work_item {
    dp_defer_work_func work_func;
    void *netdev;
    int qid;
    uint32_t attempts;
    int pkt_cnt;
    struct dp_netdev_rxq **output_pkts_rxqs;

    /* The pmd_iteration_cnt at which to the work item was deferred.  It's used
     * along with the async-iteration-delay to decide whether to attempt doing
     * a work item. */
    uint64_t pmd_iteration_cnt;
};

#define WORK_RING_SIZE 128
#define WORK_RING_MASK (WORK_RING_SIZE - 1)

#define ATTEMPT_LIMIT UINT32_MAX

/* How many iterations of pmd_thread_main() to delay checking for the
 * completion of deferred work. */
#define DEFAULT_ASYNC_ITERATION_DELAY 0

/* The read and write indexes are between 0 and 2^32, and we mask their value
 * when we access the work_ring[] array. */
struct dp_defer {
    uint32_t read_idx;
    uint32_t write_idx;
    struct dp_defer_work_item work_ring[WORK_RING_SIZE];
};

static inline void
dp_defer_init(struct dp_defer *defer)
{
    defer->read_idx = 0;
    defer->write_idx = 0;
}

static inline int
dp_defer_work_ring_empty(const struct dp_defer *defer)
{
    return defer->write_idx == defer->read_idx;
}

static inline int
dp_defer_work_ring_full(const struct dp_defer *defer)
{
    /* When the write index is exactly (WORK_RING_SIZE - 1) or WORK_RING_MASK
     * elements ahead of the read index, the ring is full. When calculating the
     * difference between the indexes, wraparound is not an issue since
     * unsigned ints are used. */
    uint16_t count = (defer->write_idx - defer->read_idx) & WORK_RING_MASK;

    return count == WORK_RING_MASK;
}

#ifdef  __cplusplus
}
#endif

#endif /* dpif-netdev-private-defer.h */
