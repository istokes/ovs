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

/* Variable to hold the default mfex implementation. */
static miniflow_extract_func default_mfex_func = NULL;

/* Implementations of available extract options and
 * the implementations are always in order of preference.
 */
static struct dpif_miniflow_extract_impl mfex_impls[] = {

    [MFEX_IMPL_SCALAR] = {
        .probe = NULL,
        .extract_func = NULL,
        .name = "scalar", },
};

BUILD_ASSERT_DECL(MFEX_IMPL_MAX >= ARRAY_SIZE(mfex_impls));

void
dpif_miniflow_extract_init(void)
{
    /* Call probe on each impl, and cache the result. */
    uint32_t i;
    for (i = 0; i < ARRAY_SIZE(mfex_impls); i++) {
        bool avail = true;
        if (mfex_impls[i].probe) {
            /* Return zero is success, non-zero means error. */
            avail = (mfex_impls[i].probe() == 0);
        }
        VLOG_INFO("Miniflow Extract implementation %s (available: %s)\n",
                  mfex_impls[i].name, avail ? "True" : "False");
        mfex_impls[i].available = avail;
    }
}

miniflow_extract_func
dp_mfex_impl_get_default(void)
{
    /* For the first call, this will be NULL. Compute the compile time default.
     */
    if (!default_mfex_func) {

        VLOG_INFO("Default MFEX implementation is %s.\n",
                  mfex_impls[MFEX_IMPL_SCALAR].name);
        default_mfex_func = mfex_impls[MFEX_IMPL_SCALAR].extract_func;
    }

    return default_mfex_func;
}

int32_t
dp_mfex_impl_set_default_by_name(const char *name)
{
    miniflow_extract_func new_default;


    int32_t err = dp_mfex_impl_get_by_name(name, &new_default);

    if (!err) {
        default_mfex_func = new_default;
    }

    return err;

}

uint32_t
dp_mfex_impl_get(struct ds *reply, struct dp_netdev_pmd_thread **pmd_list,
                 size_t n)
{
    /* Add all mfex functions to reply string. */
    ds_put_cstr(reply, "Available MFEX implementations:\n");

    for (uint32_t i = 0; i < ARRAY_SIZE(mfex_impls); i++) {

        ds_put_format(reply, "  %s (available: %s)(pmds: ",
                      mfex_impls[i].name, mfex_impls[i].available ?
                      "True" : "False");

        for (size_t j = 0; j < n; j++) {
            struct dp_netdev_pmd_thread *pmd = pmd_list[j];
            if (pmd->core_id == NON_PMD_CORE_ID) {
                continue;
            }

            if (pmd->miniflow_extract_opt == mfex_impls[i].extract_func) {
                ds_put_format(reply, "%u,", pmd->core_id);
            }
        }

        ds_chomp(reply, ',');

        if (ds_last(reply) == ' ') {
            ds_put_cstr(reply, "none");
        }

        ds_put_cstr(reply, ")\n");
    }

    return ARRAY_SIZE(mfex_impls);
}

/* This function checks all available MFEX implementations, and selects the
 * returns the function pointer to the one requested by "name".
 */
int32_t
dp_mfex_impl_get_by_name(const char *name, miniflow_extract_func *out_func)
{
    if ((name == NULL) || (out_func == NULL)) {
        return -EINVAL;
    }

    uint32_t i;

    for (i = 0; i < ARRAY_SIZE(mfex_impls); i++) {
        if (strcmp(mfex_impls[i].name, name) == 0) {
            /* Probe function is optional - so check it is set before exec. */
            if (!mfex_impls[i].available) {
                *out_func = NULL;
                return -EINVAL;
            }

            *out_func = mfex_impls[i].extract_func;
            return 0;
        }
    }

    return -EINVAL;
}
