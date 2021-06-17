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

#ifndef DPIF_NETDEV_AVX512_EXTRACT
#define DPIF_NETDEV_AVX512_EXTRACT 1

#include <sys/types.h>

#include "openvswitch/types.h"

/* Max size of dpif_miniflow_extract_impl array. */
#define MFEX_IMPLS_MAX_SIZE (16)

/* Skip the autovalidator study and null when iterating all available
 * miniflow implementations.
 */
#define MFEX_IMPL_START_IDX (3)

/* Forward declarations. */
struct dp_packet;
struct miniflow;
struct dp_netdev_pmd_thread;
struct dp_packet_batch;
struct netdev_flow_key;

/* Function pointer prototype to be implemented in the optimized miniflow
 * extract code.
 * returns the hitmask of the processed packets on success.
 * returns zero on failure.
 */
typedef uint32_t (*miniflow_extract_func)(struct dp_packet_batch *batch,
                                          struct netdev_flow_key *keys,
                                          uint32_t keys_size,
                                          odp_port_t in_port,
                                          void *pmd_handle);

/* Probe function is used to detect if this CPU has the ISA required
 * to run the optimized miniflow implementation.
 * returns one on successful probe.
 * returns zero on failure.
 */
typedef int32_t (*miniflow_extract_probe)(void);

/* Structure representing the attributes of an optimized implementation. */
struct dpif_miniflow_extract_impl {
    /* When non-zero, this impl has passed the probe() checks. */
    uint8_t available;

    /* Probe function is used to detect if this CPU has the ISA required
     * to run the optimized miniflow implementation.
     */
    miniflow_extract_probe probe;

    /* Function to call to extract miniflows for a burst of packets. */
    miniflow_extract_func extract_func;

    /* Name of the optimized implementation. */
    char *name;
};

/* Retrieve the opt structure for the requested implementation by name.
 * Returns zero on success, and opt points to a valid struct, or
 * returns a negative failure status.
 * -ENOTSUP : invalid name requested
 */
int32_t
dpif_miniflow_extract_opt_get(const char *name,
                              struct dpif_miniflow_extract_impl **opt);

/* Initializes the available miniflow extract implementations by probing for
 * the CPU ISA requirements. As the runtime available CPU ISA does not change
 * and the required ISA of the implementation also does not change, it is safe
 * to cache the probe() results, and not call probe() at runtime.
 */
void
dpif_miniflow_extract_init(void);

/* Retrieve the array of miniflow implementations for iteration.
 * On error, returns a negative number.
 * On success, returns the size of the arrays pointed to by the out parameter.
 */
int32_t
dpif_miniflow_extract_info_get(struct dpif_miniflow_extract_impl **out_ptr);

/* Retrieve the hitmask of the batch of pakcets which is obtained by comparing
 * different miniflow implementations with linear miniflow extract.
 * On error, returns a zero.
 * On success, returns the number of packets in the batch compared.
 */
uint32_t
dpif_miniflow_extract_autovalidator(struct dp_packet_batch *batch,
                                    struct netdev_flow_key *keys,
                                    uint32_t keys_size, odp_port_t in_port,
                                    void *pmd_handle);

/* Retrieve the number of packets by studying packets using different miniflow
 * implementations to choose the best implementation using the maximum hitmask
 * count.
 * On error, returns a zero for no packets.
 * On success, returns mask of the packets hit.
 */
uint32_t
mfex_study_traffic(struct dp_packet_batch *packets,
                   struct netdev_flow_key *keys,
                   uint32_t keys_size, odp_port_t in_port,
                   void *pmd_handle);

#endif /* DPIF_NETDEV_AVX512_EXTRACT */
