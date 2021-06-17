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

#include "dp-packet.h"
#include "dpif-netdev-private-dpcls.h"
#include "dpif-netdev-private-extract.h"
#include "dpif-netdev-private-thread.h"
#include "flow.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev_extract);

/* Implementations of available extract options. */
static struct dpif_miniflow_extract_impl mfex_impls[] = {
   {
        .probe = NULL,
        .extract_func = dpif_miniflow_extract_autovalidator,
        .name = "autovalidator",
    },
    {
        .probe = NULL,
        .extract_func = NULL,
        .name = "disable",
    },
    {
        .probe = NULL,
        .extract_func = mfex_study_traffic,
        .name = "study",
    },

/* Compile in implementations only if the compiler ISA checks pass. */
#if (__x86_64__ && HAVE_AVX512F && HAVE_LD_AVX512_GOOD && __SSE4_2__)
    {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_ip_udp,
        .name = "avx512_vbmi_ipv4_udp",
    },
    {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_ip_udp,
        .name = "avx512_ipv4_udp",
    },
    {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_ip_tcp,
        .name = "avx512_vbmi_ipv4_tcp",
    },
    {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_ip_tcp,
        .name = "avx512_ipv4_tcp",
    },

    {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_dot1q_ip_udp,
        .name = "avx512_vbmi_dot1q_ipv4_udp",
    },
    {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_dot1q_ip_udp,
        .name = "avx512_dot1q_ipv4_udp",
    },
    {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_dot1q_ip_tcp,
        .name = "avx512_vbmi_dot1q_ipv4_tcp",
    },
    {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_dot1q_ip_tcp,
        .name = "avx512_dot1q_ipv4_tcp",
    },
#endif
};


BUILD_ASSERT_DECL(MFEX_IMPLS_MAX_SIZE > ARRAY_SIZE(mfex_impls));

int32_t
dpif_miniflow_extract_opt_get(const char *name,
                              struct dpif_miniflow_extract_impl **opt)
{
    ovs_assert(opt);
    ovs_assert(name);

    uint32_t i;
    for (i = 0; i < ARRAY_SIZE(mfex_impls); i++) {
        if (strcmp(name, mfex_impls[i].name) == 0) {
            *opt = &mfex_impls[i];
            return 0;
        }
    }
    return -ENOTSUP;
}

void
dpif_miniflow_extract_init(void)
{
    /* Call probe on each impl, and cache the result. */
    uint32_t i;
    for (i = 0; i < ARRAY_SIZE(mfex_impls); i++) {
        int avail = 1;
        if (mfex_impls[i].probe) {
            /* Return zero is success, non-zero means error. */
            avail = (mfex_impls[i].probe() == 0);
        }
        VLOG_INFO("Miniflow Extract implementation %s (available: %s)\n",
                  mfex_impls[i].name, avail ? "True" : "False");
        mfex_impls[i].available = avail;
    }
}

int32_t
dpif_miniflow_extract_info_get(struct dpif_miniflow_extract_impl **out_ptr)
{
    if (out_ptr == NULL) {
        return -EINVAL;
    }
    *out_ptr = mfex_impls;
    return ARRAY_SIZE(mfex_impls);
}

uint32_t
dpif_miniflow_extract_autovalidator(struct dp_packet_batch *packets,
                                    struct netdev_flow_key *keys,
                                    uint32_t keys_size, odp_port_t in_port,
                                    void *pmd_handle)
{
    const size_t cnt = dp_packet_batch_size(packets);
    uint16_t good_l2_5_ofs[NETDEV_MAX_BURST];
    uint16_t good_l3_ofs[NETDEV_MAX_BURST];
    uint16_t good_l4_ofs[NETDEV_MAX_BURST];
    uint16_t good_l2_pad_size[NETDEV_MAX_BURST];
    struct dp_packet *packet;
    struct dp_netdev_pmd_thread *pmd = pmd_handle;
    struct dpif_miniflow_extract_impl *miniflow_funcs;

    int32_t mfunc_count = dpif_miniflow_extract_info_get(&miniflow_funcs);
    if (mfunc_count < 0) {
        pmd->miniflow_extract_opt = NULL;
        VLOG_ERR("failed to get miniflow extract function implementations\n");
        return 0;
    }
    ovs_assert(keys_size >= cnt);
    struct netdev_flow_key test_keys[NETDEV_MAX_BURST];

    /* Run scalar miniflow_extract to get default result. */
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets) {
        pkt_metadata_init(&packet->md, in_port);
        miniflow_extract(packet, &keys[i].mf);

        /* Store known good metadata to compare with optimized metadata. */
        good_l2_5_ofs[i] = packet->l2_5_ofs;
        good_l3_ofs[i] = packet->l3_ofs;
        good_l4_ofs[i] = packet->l4_ofs;
        good_l2_pad_size[i] = packet->l2_pad_size;
    }

    /* Iterate through each version of miniflow implementations. */
    for (int j = MFEX_IMPL_START_IDX; j < ARRAY_SIZE(mfex_impls); j++) {
        if (!mfex_impls[j].available) {
            continue;
        }

        /* Reset keys and offsets before each implementation. */
        memset(test_keys, 0, keys_size * sizeof(struct netdev_flow_key));
        DP_PACKET_BATCH_FOR_EACH (i, packet, packets) {
            dp_packet_reset_offsets(packet);
        }
        /* Call optimized miniflow for each batch of packet. */
        uint32_t hit_mask = mfex_impls[j].extract_func(packets, test_keys,
                                            keys_size, in_port, pmd_handle);

        /* Do a miniflow compare for bits, blocks and offsets for all the
         * classified packets in the hitmask marked by set bits. */
        while (hit_mask) {
            /* Index for the set bit. */
            uint32_t i = __builtin_ctz(hit_mask);
            /* Set the index in hitmask to Zero. */
            hit_mask &= (hit_mask - 1);

            uint32_t failed = 0;

            /* Check miniflow bits are equal. */
            if ((keys[i].mf.map.bits[0] != test_keys[i].mf.map.bits[0]) ||
                (keys[i].mf.map.bits[1] != test_keys[i].mf.map.bits[1])) {
                VLOG_ERR("Good 0x%llx 0x%llx\tTest 0x%llx 0x%llx\n",
                         keys[i].mf.map.bits[0], keys[i].mf.map.bits[1],
                         test_keys[i].mf.map.bits[0],
                         test_keys[i].mf.map.bits[1]);
                failed = 1;
            }

            if (!miniflow_equal(&keys[i].mf, &test_keys[i].mf)) {
                uint32_t block_cnt = miniflow_n_values(&keys[i].mf);
                VLOG_ERR("Autovalidation blocks failed for %s pkt %d",
                         mfex_impls[j].name, i);
                VLOG_ERR("  Good hexdump:\n");
                uint64_t *good_block_ptr = (uint64_t *)&keys[i].buf;
                uint64_t *test_block_ptr = (uint64_t *)&test_keys[i].buf;
                for (uint32_t b = 0; b < block_cnt; b++) {
                    VLOG_ERR("    %"PRIx64"\n", good_block_ptr[b]);
                }
                VLOG_ERR("  Test hexdump:\n");
                for (uint32_t b = 0; b < block_cnt; b++) {
                    VLOG_ERR("    %"PRIx64"\n", test_block_ptr[b]);
                }
                failed = 1;
            }

            if ((packets->packets[i]->l2_pad_size != good_l2_pad_size[i]) ||
                    (packets->packets[i]->l2_5_ofs != good_l2_5_ofs[i]) ||
                    (packets->packets[i]->l3_ofs != good_l3_ofs[i]) ||
                    (packets->packets[i]->l4_ofs != good_l4_ofs[i])) {
                VLOG_ERR("Autovalidation packet offsets failed for %s pkt %d",
                         mfex_impls[j].name, i);
                VLOG_ERR("  Good offsets: l2_pad_size %u, l2_5_ofs : %u"
                         " l3_ofs %u, l4_ofs %u\n",
                         good_l2_pad_size[i], good_l2_5_ofs[i],
                         good_l3_ofs[i], good_l4_ofs[i]);
                VLOG_ERR("  Test offsets: l2_pad_size %u, l2_5_ofs : %u"
                         " l3_ofs %u, l4_ofs %u\n",
                         packets->packets[i]->l2_pad_size,
                         packets->packets[i]->l2_5_ofs,
                         packets->packets[i]->l3_ofs,
                         packets->packets[i]->l4_ofs);
                failed = 1;
            }

            if (failed) {
                /* Having dumped the debug info, disable autovalidator. */
                VLOG_ERR("Autovalidation failed in %s pkt %d, disabling.\n",
                         mfex_impls[j].name, i);
                /* Halt OVS here on debug builds. */
                ovs_assert(0);
                pmd->miniflow_extract_opt = NULL;
                break;
            }
        }
    }

    /* preserve packet correctness by storing back the good offsets in
     * packets back. */
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets) {
        packet->l2_5_ofs = good_l2_5_ofs[i];
        packet->l3_ofs = good_l3_ofs[i];
        packet->l4_ofs = good_l4_ofs[i];
        packet->l2_pad_size = good_l2_pad_size[i];
    }

    /* Returning zero implies no packets were hit by autovalidation. This
     * simplifies unit-tests as changing --enable-mfex-default-autovalidator
     * would pass/fail. By always returning zero, autovalidator is a little
     * slower, but we gain consistency in testing.
     */
    return 0;
}

/* Variable to hold the defaualt mfex implementation. */
static miniflow_extract_func default_mfex_func = NULL;

void
dpif_miniflow_extract_set_default(miniflow_extract_func func)
{
    default_mfex_func = func;
}

miniflow_extract_func
dpif_miniflow_extract_get_default(void)
{

#ifdef MFEX_AUTOVALIDATOR_DEFAULT
    ovs_assert(mfex_impls[0].extract_func ==
               dpif_miniflow_extract_autovalidator);
    VLOG_INFO("Default miniflow Extract implementation %s \n",
              mfex_impls[0].name);
    return mfex_impls[0].extract_func;
#else
    return default_mfex_func;
#endif
}
