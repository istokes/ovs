/*
 * Copyright (c) 2021 Intel.
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
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "dpif-netdev-private-extract.h"
#include "dpif-netdev-private-thread.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"

VLOG_DEFINE_THIS_MODULE(dpif_mfex_extract_study);

/* Max size of packets to be compared. */
#define MFEX_MAX_COUNT (128)

/* This value is the threshold for the amount of packets that
 * must hit on the optimized miniflow extract before it will be
 * accepted and used in the datapath after the study phase. */
#define MFEX_MIN_HIT_COUNT_FOR_USE (MFEX_MAX_COUNT / 2)

/* Struct to hold miniflow study stats. */
struct study_stats {
    uint32_t pkt_count;
    uint32_t impl_hitcount[MFEX_IMPLS_MAX_SIZE];
};

/* Define per thread data to hold the study stats. */
DEFINE_PER_THREAD_MALLOCED_DATA(struct study_stats *, study_stats);

/* Allocate per thread PMD pointer space for study_stats. */
static inline struct study_stats *
get_study_stats(void)
{
    struct study_stats *stats = study_stats_get();
    if (OVS_UNLIKELY(!stats)) {
       stats = xzalloc(sizeof *stats);
       study_stats_set_unsafe(stats);
    }
    return stats;
}

uint32_t
mfex_study_traffic(struct dp_packet_batch *packets,
                   struct netdev_flow_key *keys,
                   uint32_t keys_size, odp_port_t in_port,
                   void *pmd_handle)
{
    uint32_t hitmask = 0;
    uint32_t mask = 0;
    struct dp_netdev_pmd_thread *pmd = pmd_handle;
    struct dpif_miniflow_extract_impl *miniflow_funcs;
    uint32_t impl_count = dpif_miniflow_extract_info_get(&miniflow_funcs);
    struct study_stats *stats = get_study_stats();

    /* Run traffic optimized miniflow_extract to collect the hitmask
     * to be compared after certain packets have been hit to choose
     * the best miniflow_extract version for that traffic. */
    for (int i = MFEX_IMPL_START_IDX; i < impl_count; i++) {
        if (miniflow_funcs[i].available) {
            hitmask = miniflow_funcs[i].extract_func(packets, keys, keys_size,
                                                     in_port, pmd_handle);
            stats->impl_hitcount[i] += count_1bits(hitmask);

            /* If traffic is not classified than we dont overwrite the keys
             * array in minfiflow implementations so its safe to create a
             * mask for all those packets whose miniflow have been created. */
            mask |= hitmask;
        }
    }
    stats->pkt_count += dp_packet_batch_size(packets);

    /* Choose the best implementation after a minimum packets have been
     * processed. */
    if (stats->pkt_count >= MFEX_MAX_COUNT) {
        uint32_t best_func_index = MFEX_IMPL_START_IDX;
        uint32_t max_hits = 0;
        for (int i = MFEX_IMPL_START_IDX; i < impl_count; i++) {
            if (stats->impl_hitcount[i] > max_hits) {
                max_hits = stats->impl_hitcount[i];
                best_func_index = i;
            }
        }

        if (max_hits >= MFEX_MIN_HIT_COUNT_FOR_USE) {
            /* Set the implementation to index with max_hits. */
            pmd->miniflow_extract_opt =
                        miniflow_funcs[best_func_index].extract_func;
            VLOG_INFO("MFEX study chose impl %s: (hits %d/%d pkts)\n",
                      miniflow_funcs[best_func_index].name, max_hits,
                      stats->pkt_count);
        } else {
            /* Set the implementation to null for default miniflow. */
            pmd->miniflow_extract_opt = NULL;
            VLOG_INFO("Not enough packets matched (%d/%d), disabling"
                      " optimized MFEX.\n", max_hits, stats->pkt_count);
        }
        /* Reset stats so that study function can be called again
         * for next traffic type and optimal function ptr can be
         * choosen. */
        memset(stats, 0, sizeof(struct study_stats));
    }
    return mask;
}
