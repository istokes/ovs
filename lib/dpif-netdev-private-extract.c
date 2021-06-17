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
        .extract_func = NULL,
        .name = "disable",
    },
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
