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

#include <config.h>
#include <errno.h>
#include <string.h>

#include "dpif-netdev-private-dpif.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev_impl);

/* Actual list of implementations goes here. */
static struct dpif_netdev_impl_info_t dpif_impls[] = {
    /* The default scalar C code implementation. */
    { .func = dp_netdev_input,
      .probe = NULL,
      .name = "dpif_scalar", },

#if (__x86_64__ && HAVE_AVX512F && HAVE_LD_AVX512_GOOD && __SSE4_2__)
    /* Only available on x86_64 bit builds with SSE 4.2 used for OVS core. */
    { .func = dp_netdev_input_outer_avx512,
      .probe = dp_netdev_input_outer_avx512_probe,
      .name = "dpif_avx512", },
#endif
};

static dp_netdev_input_func default_dpif_func;

dp_netdev_input_func
dp_netdev_impl_get_default(void)
{
    /* For the first call, this will be NULL. Compute the compile time default.
     */
    if (!default_dpif_func) {
        int dpif_idx = 0;

/* Configure-time overriding to run test suite on all implementations. */
#if (__x86_64__ && HAVE_AVX512F && HAVE_LD_AVX512_GOOD && __SSE4_2__)
#ifdef DPIF_AVX512_DEFAULT
        ovs_assert(dpif_impls[1].func == dp_netdev_input_outer_avx512);
        if (!dp_netdev_input_outer_avx512_probe()) {
            dpif_idx = 1;
        };
#endif
#endif

        VLOG_INFO("Default DPIF implementation is %s.\n",
                  dpif_impls[dpif_idx].name);
        default_dpif_func = dpif_impls[dpif_idx].func;
    }

    return default_dpif_func;
}

void
dp_netdev_impl_set_default(dp_netdev_input_func func)
{
    default_dpif_func = func;
}

/* This function checks all available DPIF implementations, and selects the
 * returns the function pointer to the one requested by "name".
 */
int32_t
dp_netdev_impl_get_by_name(const char *name, dp_netdev_input_func *out_func)
{
    ovs_assert(name);
    ovs_assert(out_func);

    uint32_t i;

    for (i = 0; i < ARRAY_SIZE(dpif_impls); i++) {
        if (strcmp(dpif_impls[i].name, name) == 0) {
            /* Probe function is optional - so check it is set before exec. */
            if (dpif_impls[i].probe) {
                int probe_err = dpif_impls[i].probe();
                if (probe_err) {
                  *out_func = NULL;
                   return probe_err;
                }
            }
            *out_func = dpif_impls[i].func;
            return 0;
        }
    }

    return -EINVAL;
}
