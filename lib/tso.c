/*
 * Copyright (c) 2020 Red Hat, Inc.
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

#include "smap.h"
#include "ovs-thread.h"
#include "openvswitch/vlog.h"
#include "dpdk.h"
#include "tso.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(tso);

static bool tso_support_enabled = false;

void
tso_init(const struct smap *ovs_other_config)
{
    if (smap_get_bool(ovs_other_config, "tso-support", false)) {
        static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once)) {
            if (dpdk_available()) {
                VLOG_INFO("TCP Segmentation Offloading (TSO) support enabled");
                tso_support_enabled = true;
            } else {
                VLOG_ERR("TCP Segmentation Offloading (TSO) is unsupported "
                         "without enabling DPDK");
                tso_support_enabled = false;
            }
            ovsthread_once_done(&once);
        }
    }
}

bool
tso_enabled(void)
{
    return tso_support_enabled;
}
