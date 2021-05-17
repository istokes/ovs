/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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

#ifndef DPIF_NETDEV_PRIVATE_HWOL_H
#define DPIF_NETDEV_PRIVATE_HWOL_H 1

#include "dpif-netdev-private-flow.h"

#define MAX_FLOW_MARK       (UINT32_MAX - 1)
#define INVALID_FLOW_MARK   0
/* Zero flow mark is used to indicate the HW to remove the mark. A packet
 * marked with zero mark is received in SW without a mark at all, so it
 * cannot be used as a valid mark.
 */

struct megaflow_to_mark_data {
    const struct cmap_node node;
    ovs_u128 mega_ufid;
    uint32_t mark;
};

struct flow_mark {
    struct cmap megaflow_to_mark;
    struct cmap mark_to_flow;
    struct id_pool *pool;
};

/* allocated in dpif-netdev.c */
extern struct flow_mark flow_mark;

static inline struct dp_netdev_flow *
mark_to_flow_find(const struct dp_netdev_pmd_thread *pmd,
                  const uint32_t mark)
{
    struct dp_netdev_flow *flow;

    CMAP_FOR_EACH_WITH_HASH (flow, mark_node, hash_int(mark, 0),
                             &flow_mark.mark_to_flow) {
        if (flow->mark == mark && flow->pmd_id == pmd->core_id &&
            flow->dead == false) {
            return flow;
        }
    }

    return NULL;
}


#endif /* dpif-netdev-private-hwol.h */
