/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

#ifndef DPBUF_H
#define DPBUF_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef DPDK_NETDEV
#include <rte_config.h>
#include <rte_mbuf.h>
#endif

#include "netdev-dpdk.h"
#include "openvswitch/list.h"
#include "util.h"
#include "flow.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum OVS_PACKED_ENUM dp_packet_source {
    DPBUF_MALLOC,              /* Obtained via malloc(). */
    DPBUF_STACK,               /* Un-movable stack space or static buffer. */
    DPBUF_STUB,                /* Starts on stack, may expand into heap. */
    DPBUF_DPDK,                /* buffer data is from DPDK allocated memory.
                                * ref to dp_packet_init_dpdk() in dp-packet.c.
                                */
};

#define DP_PACKET_CONTEXT_SIZE 64

#ifdef DPDK_NETDEV
/* Struct to save data for when a DPBUF_DPDK packet is converted to
 * DPBUF_MALLOC. */
struct mbuf_state {
    void *addr;
    uint16_t len;
    uint16_t off;
};
#endif

/* Buffer for holding packet data.  A dp_packet is automatically reallocated
 * as necessary if it grows too large for the available memory.
 * By default the packet type is set to Ethernet (PT_ETH).
 */
struct dp_packet {
#ifdef DPDK_NETDEV
    struct rte_mbuf mbuf;       /* DPDK mbuf */
    struct mbuf_state *mstate;  /* Used when packet has been "linearized" */
#else
    void *base_;                /* First byte of allocated space. */
    uint16_t allocated_;        /* Number of bytes allocated. */
    uint16_t data_ofs;          /* First byte actually in use. */
    uint32_t size_;             /* Number of bytes in use. */
    uint32_t rss_hash;          /* Packet hash. */
    bool rss_hash_valid;        /* Is the 'rss_hash' valid? */
#endif
    enum dp_packet_source source;  /* Source of memory allocated as 'base'. */

    /* All the following elements of this struct are copied in a single call
     * of memcpy in dp_packet_clone_with_headroom. */
    uint8_t l2_pad_size;           /* Detected l2 padding size.
                                    * Padding is non-pullable. */
    uint16_t l2_5_ofs;             /* MPLS label stack offset, or UINT16_MAX */
    uint16_t l3_ofs;               /* Network-level header offset,
                                    * or UINT16_MAX. */
    uint16_t l4_ofs;               /* Transport-level header offset,
                                      or UINT16_MAX. */
    uint32_t cutlen;               /* length in bytes to cut from the end. */
    ovs_be32 packet_type;          /* Packet type as defined in OpenFlow */
    union {
        struct pkt_metadata md;
        uint64_t data[DP_PACKET_CONTEXT_SIZE / 8];
    };
};

static inline void *dp_packet_data(const struct dp_packet *);
static inline void dp_packet_set_data(struct dp_packet *, void *);
static inline void *dp_packet_base(const struct dp_packet *);
static inline void dp_packet_set_base(struct dp_packet *, void *);

static inline bool dp_packet_is_linear(const struct dp_packet *);
static inline void dp_packet_linearize(struct dp_packet *);

static inline uint32_t dp_packet_size(const struct dp_packet *);
static inline void dp_packet_set_size(struct dp_packet *, uint32_t);

static inline uint16_t dp_packet_get_allocated(const struct dp_packet *);
static inline void dp_packet_set_allocated(struct dp_packet *, uint16_t);

void *dp_packet_resize_l2(struct dp_packet *, int increment);
void *dp_packet_resize_l2_5(struct dp_packet *, int increment);
static inline void *dp_packet_eth(const struct dp_packet *);
static inline void dp_packet_reset_offsets(struct dp_packet *);
static inline uint8_t dp_packet_l2_pad_size(const struct dp_packet *);
static inline void dp_packet_set_l2_pad_size(struct dp_packet *, uint8_t);
static inline void *dp_packet_l2_5(const struct dp_packet *);
static inline void dp_packet_set_l2_5(struct dp_packet *, void *);
static inline void *dp_packet_l3(const struct dp_packet *);
static inline void dp_packet_set_l3(struct dp_packet *, void *);
static inline size_t dp_packet_l3_size(const struct dp_packet *);
static inline void *dp_packet_l4(const struct dp_packet *);
static inline void dp_packet_set_l4(struct dp_packet *, void *);
static inline size_t dp_packet_l4_size(const struct dp_packet *);
static inline const void *dp_packet_get_tcp_payload(const struct dp_packet *);
static inline const void *dp_packet_get_udp_payload(const struct dp_packet *);
static inline const void *dp_packet_get_sctp_payload(const struct dp_packet *);
static inline const void *dp_packet_get_icmp_payload(const struct dp_packet *);
static inline const void *dp_packet_get_nd_payload(const struct dp_packet *);

void dp_packet_use(struct dp_packet *, void *, size_t);
void dp_packet_use_stub(struct dp_packet *, void *, size_t);
void dp_packet_use_const(struct dp_packet *, const void *, size_t);

void dp_packet_init_dpdk(struct dp_packet *);

void dp_packet_init(struct dp_packet *, size_t);
void dp_packet_uninit(struct dp_packet *);

struct dp_packet *dp_packet_new(size_t);
struct dp_packet *dp_packet_new_with_headroom(size_t, size_t headroom);
struct dp_packet *dp_packet_clone(const struct dp_packet *);
struct dp_packet *dp_packet_clone_with_headroom(const struct dp_packet *,
                                                size_t headroom);
struct dp_packet *dp_packet_clone_data(const void *, size_t);
struct dp_packet *dp_packet_clone_data_with_headroom(const void *, size_t,
                                                     size_t headroom);
static inline void dp_packet_delete(struct dp_packet *);

static inline void
dp_packet_copy_common_members(struct dp_packet *new_b,
                              const struct dp_packet *b);

static inline void *dp_packet_at(const struct dp_packet *, size_t offset,
                                 size_t size);
static inline void *dp_packet_at_assert(const struct dp_packet *,
                                        size_t offset, size_t size);

static inline void
dp_packet_copy_from_offset(const struct dp_packet *b, size_t offset,
                           size_t size, void *buf);

#ifdef DPDK_NETDEV
static inline const struct rte_mbuf *
dp_packet_mbuf_from_offset(const struct dp_packet *b, size_t *offset);
void
dp_packet_mbuf_write(struct rte_mbuf *mbuf, int16_t ofs, uint32_t len,
                     const void *data);
static inline void
dp_packet_copy_mbuf_flags(struct dp_packet *dst, const struct dp_packet *src);
#endif
static inline void *dp_packet_tail(const struct dp_packet *);
static inline void *dp_packet_end(const struct dp_packet *);

void *dp_packet_put_uninit(struct dp_packet *, size_t);
void *dp_packet_put_zeros(struct dp_packet *, size_t);
void *dp_packet_put(struct dp_packet *, const void *, size_t);
char *dp_packet_put_hex(struct dp_packet *, const char *s, size_t *n);
void dp_packet_reserve(struct dp_packet *, size_t);
void dp_packet_reserve_with_tailroom(struct dp_packet *, size_t headroom,
                                     size_t tailroom);
void *dp_packet_push_uninit(struct dp_packet *, size_t);
void *dp_packet_push_zeros(struct dp_packet *, size_t);
void *dp_packet_push(struct dp_packet *, const void *, size_t);

static inline size_t dp_packet_headroom(const struct dp_packet *);
static inline size_t dp_packet_tailroom(const struct dp_packet *);
void dp_packet_prealloc_headroom(struct dp_packet *, size_t);
void dp_packet_prealloc_tailroom(struct dp_packet *, size_t);
void dp_packet_shift(struct dp_packet *, int);

static inline void dp_packet_clear(struct dp_packet *);
static inline void *dp_packet_pull(struct dp_packet *, size_t);
static inline void *dp_packet_try_pull(struct dp_packet *, size_t);

void *dp_packet_steal_data(struct dp_packet *);

static inline bool dp_packet_equal(const struct dp_packet *,
                                   const struct dp_packet *);

static inline ssize_t
dp_packet_read_data(const struct dp_packet *b, size_t offset, size_t size,
                    void **ptr, void *buf);



/* Frees memory that 'b' points to, as well as 'b' itself. */
static inline void
dp_packet_delete(struct dp_packet *b)
{
    if (b) {
        dp_packet_uninit(b);

        if (b->source != DPBUF_DPDK) {
            free(b);
        }
    }
}

/* Copies the following fields into the 'new_b', which represent the common
 * fields between DPDK and non-DPDK packets: l2_pad_size, l2_5_ofs, l3_ofs,
 * l4_ofs, cutlen, packet_type and md. */
static inline void
dp_packet_copy_common_members(struct dp_packet *new_b,
                              const struct dp_packet *b) {
    memcpy(&new_b->l2_pad_size, &b->l2_pad_size,
           sizeof(struct dp_packet) -
           offsetof(struct dp_packet, l2_pad_size));
}

/* If 'b' contains at least 'offset + size' bytes of data, returns a pointer to
 * byte 'offset'.  Otherwise, returns a null pointer. For DPDK packets, this
 * means the 'offset' + 'size' must fall within the same mbuf (not necessarily
 * the first mbuf), otherwise null is returned */
static inline void *
dp_packet_at(const struct dp_packet *b, size_t offset, size_t size)
{
    if (offset + size > dp_packet_size(b)) {
        return NULL;
    }

#ifdef DPDK_NETDEV
    if (b->source == DPBUF_DPDK) {
        const struct rte_mbuf *mbuf = dp_packet_mbuf_from_offset(b, &offset);

        if (!mbuf || offset + size > mbuf->data_len) {
            return NULL;
        }

        return rte_pktmbuf_mtod_offset(mbuf, char *, offset);
    }
#endif
    return (char *) dp_packet_data(b) + offset;
}

/* Returns a pointer to byte 'offset' in 'b', which must contain at least
 * 'offset + size' bytes of data. */
static inline void *
dp_packet_at_assert(const struct dp_packet *b, size_t offset, size_t size)
{
    ovs_assert(offset + size <= dp_packet_size(b));
    return dp_packet_at(b, offset, size);
}

/* Returns a pointer to byte following the last byte of data in use in 'b'. */
static inline void *
dp_packet_tail(const struct dp_packet *b)
{
#ifdef DPDK_NETDEV
    if (b->source == DPBUF_DPDK) {
        struct rte_mbuf *buf = CONST_CAST(struct rte_mbuf *, &b->mbuf);
        /* Find last segment where data ends, meaning the tail of the chained
         *  mbufs must be there */
        buf = rte_pktmbuf_lastseg(buf);

        return rte_pktmbuf_mtod_offset(buf, void *, buf->data_len);
    }
#endif
    return (char *) dp_packet_data(b) + dp_packet_size(b);
}

/* Returns a pointer to byte following the last byte allocated for use (but
 * not necessarily in use) in 'b'. */
static inline void *
dp_packet_end(const struct dp_packet *b)
{
#ifdef DPDK_NETDEV
    if (b->source == DPBUF_DPDK) {
        struct rte_mbuf *buf = CONST_CAST(struct rte_mbuf *, &(b->mbuf));

        buf = rte_pktmbuf_lastseg(buf);

        return (char *) buf->buf_addr + buf->buf_len;
    }
#endif
    return (char *) dp_packet_base(b) + dp_packet_get_allocated(b);
}

/* Returns the number of bytes of headroom in 'b', that is, the number of bytes
 * of unused space in dp_packet 'b' before the data that is in use.  (Most
 * commonly, the data in a dp_packet is at its beginning, and thus the
 * dp_packet's headroom is 0.) */
static inline size_t
dp_packet_headroom(const struct dp_packet *b)
{
    return (char *) dp_packet_data(b) - (char *) dp_packet_base(b);
}

/* Returns the number of bytes that may be appended to the tail end of
 * dp_packet 'b' before the dp_packet must be reallocated. */
static inline size_t
dp_packet_tailroom(const struct dp_packet *b)
{
    return (char *) dp_packet_end(b) - (char *) dp_packet_tail(b);
}

/* Clears any data from 'b'. */
static inline void
dp_packet_clear(struct dp_packet *b)
{
#ifdef DPDK_NETDEV
    if (b->source == DPBUF_DPDK) {
        /* sets pkt_len and data_len to zero and frees unused mbufs */
        dp_packet_set_size(b, 0);
        rte_pktmbuf_reset(&b->mbuf);

        return;
    }
#endif
    dp_packet_set_data(b, dp_packet_base(b));
    dp_packet_set_size(b, 0);
}

/* Removes 'size' bytes from the head end of 'b', which must contain at least
 * 'size' bytes of data.  Returns the first byte of data removed. */
static inline void *
dp_packet_pull(struct dp_packet *b, size_t size)
{
    void *data = dp_packet_data(b);
    ovs_assert(dp_packet_size(b) - dp_packet_l2_pad_size(b) >= size);
    dp_packet_set_data(b, (char *) dp_packet_data(b) + size);
#ifdef DPDK_NETDEV
    b->mbuf.pkt_len -= size;
#else
    b->size_ -= size;
#endif

    return data;
}

/* Similar to dp_packet_try_pull() but doesn't actually pull any data, only
 * checks if it could and returns 'true' or 'false', accordingly. For DPDK
 * packets, 'true' is only returned in case the 'offset' + 'size' falls within
 * the first mbuf, otherwise 'false' is returned */
static inline bool
dp_packet_may_pull(const struct dp_packet *b, uint16_t offset, size_t size)
{
    if (offset == UINT16_MAX) {
        return false;
    }
#ifdef DPDK_NETDEV
    /* Offset needs to be within the first mbuf */
    if (offset + size > b->mbuf.data_len) {
        return false;
    }
#endif
    return (offset + size > dp_packet_size(b)) ? false : true;
}

/* If 'b' has at least 'size' bytes of data, removes that many bytes from the
 * head end of 'b' and returns the first byte removed.  Otherwise, returns a
 * null pointer without modifying 'b'. */
static inline void *
dp_packet_try_pull(struct dp_packet *b, size_t size)
{
#ifdef DPDK_NETDEV
    if (!dp_packet_may_pull(b, 0, size)) {
        return NULL;
    }
#endif

    return dp_packet_size(b) - dp_packet_l2_pad_size(b) >= size
        ? dp_packet_pull(b, size) : NULL;
}

/* Reads 'size' bytes from 'offset' in 'b', linearly, to 'ptr', if 'buf' is
 * NULL. Otherwise, if a 'buf' is provided, it must have 'size' bytes, and the
 * data will be copied there, iff it is found to be non-linear. */
static inline ssize_t
dp_packet_read_data(const struct dp_packet *b, size_t offset, size_t size,
                    void **ptr, void *buf) {
    /* Zero copy */
    if ((*ptr = dp_packet_at(b, offset, size)) != NULL) {
        return 0;
    }

    /* Copy available linear data */
    if (buf == NULL) {
#ifdef DPDK_NETDEV
        size_t mofs = offset;
        const struct rte_mbuf *mbuf = dp_packet_mbuf_from_offset(b, &mofs);
        *ptr = dp_packet_at(b, offset, mbuf->data_len - mofs);

        return size - (mbuf->data_len - mofs);
#else
        /* Non-DPDK dp_packets should always hit the above condition */
        ovs_assert(1);
#endif
    }

    /* Copy all data */

    *ptr = buf;
    dp_packet_copy_from_offset(b, offset, size, buf);

    return 0;
}

static inline bool
dp_packet_is_eth(const struct dp_packet *b)
{
    return b->packet_type == htonl(PT_ETH);
}

/* Get the start of the Ethernet frame. 'l3_ofs' marks the end of the l2
 * headers, so return NULL if it is not set. */
static inline void *
dp_packet_eth(const struct dp_packet *b)
{
    return (dp_packet_is_eth(b) && b->l3_ofs != UINT16_MAX)
            ? dp_packet_data(b) : NULL;
}

/* Resets all layer offsets.  'l3' offset must be set before 'l2' can be
 * retrieved. */
static inline void
dp_packet_reset_offsets(struct dp_packet *b)
{
    b->l2_pad_size = 0;
    b->l2_5_ofs = UINT16_MAX;
    b->l3_ofs = UINT16_MAX;
    b->l4_ofs = UINT16_MAX;
}

static inline uint8_t
dp_packet_l2_pad_size(const struct dp_packet *b)
{
    return b->l2_pad_size;
}

static inline void
dp_packet_set_l2_pad_size(struct dp_packet *b, uint8_t pad_size)
{
    ovs_assert(pad_size <= dp_packet_size(b));
    b->l2_pad_size = pad_size;
}

static inline void *
dp_packet_l2_5(const struct dp_packet *b)
{
    return b->l2_5_ofs != UINT16_MAX
           ? (char *) dp_packet_data(b) + b->l2_5_ofs
           : NULL;
}

static inline void
dp_packet_set_l2_5(struct dp_packet *b, void *l2_5)
{
    b->l2_5_ofs = l2_5
                  ? (char *) l2_5 - (char *) dp_packet_data(b)
                  : UINT16_MAX;
}

static inline void *
dp_packet_l3(const struct dp_packet *b)
{
    return b->l3_ofs != UINT16_MAX
           ? (char *) dp_packet_data(b) + b->l3_ofs
           : NULL;
}

static inline void
dp_packet_set_l3(struct dp_packet *b, void *l3)
{
    b->l3_ofs = l3 ? (char *) l3 - (char *) dp_packet_data(b) : UINT16_MAX;
}

/* Returns the size of the l3 header. Caller must make sure both l3_ofs and
 * l4_ofs are set*/
static inline size_t
dp_packet_l3h_size(const struct dp_packet *b)
{
    return b->l4_ofs - b->l3_ofs;
}

static inline size_t
dp_packet_l3_size(const struct dp_packet *b)
{
    if (!dp_packet_may_pull(b, b->l3_ofs, 0)) {
        return 0;
    }

    size_t l3_size = dp_packet_size(b) - b->l3_ofs;

    return l3_size - dp_packet_l2_pad_size(b);
}

static inline void *
dp_packet_l4(const struct dp_packet *b)
{
    return b->l4_ofs != UINT16_MAX
           ? (char *) dp_packet_data(b) + b->l4_ofs
           : NULL;
}

static inline void
dp_packet_set_l4(struct dp_packet *b, void *l4)
{
    b->l4_ofs = l4 ? (char *) l4 - (char *) dp_packet_data(b) : UINT16_MAX;
}

static inline size_t
dp_packet_l4_size(const struct dp_packet *b)
{
    if (!dp_packet_may_pull(b, b->l4_ofs, 0)) {
        return 0;
    }

    size_t l4_size = dp_packet_size(b) - b->l4_ofs;

    return l4_size - dp_packet_l2_pad_size(b);
}

static inline const void *
dp_packet_get_tcp_payload(const struct dp_packet *b)
{
    size_t l4_size = dp_packet_l4_size(b);

    if (OVS_LIKELY(l4_size >= TCP_HEADER_LEN)) {
        struct tcp_header *tcp = dp_packet_l4(b);
        int tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;

        if (OVS_LIKELY(tcp_len >= TCP_HEADER_LEN && tcp_len <= l4_size)) {
            tcp = dp_packet_at(b, b->l4_ofs, tcp_len);
            return (tcp == NULL) ? NULL : tcp + tcp_len;
        }
    }
    return NULL;
}

static inline const void *
dp_packet_get_udp_payload(const struct dp_packet *b)
{
    return OVS_LIKELY(dp_packet_l4_size(b) >= UDP_HEADER_LEN)
        ? (const char *) dp_packet_l4(b) + UDP_HEADER_LEN
        : NULL;
}

static inline const void *
dp_packet_get_sctp_payload(const struct dp_packet *b)
{
    return OVS_LIKELY(dp_packet_l4_size(b) >= SCTP_HEADER_LEN)
        ? (const char *) dp_packet_l4(b) + SCTP_HEADER_LEN
        : NULL;
}

static inline const void *
dp_packet_get_icmp_payload(const struct dp_packet *b)
{
    return OVS_LIKELY(dp_packet_l4_size(b) >= ICMP_HEADER_LEN)
        ? (const char *) dp_packet_l4(b) + ICMP_HEADER_LEN
        : NULL;
}

static inline const void *
dp_packet_get_nd_payload(const struct dp_packet *b)
{
    return OVS_LIKELY(dp_packet_l4_size(b) >= ND_MSG_LEN)
        ? (const char *)dp_packet_l4(b) + ND_MSG_LEN : NULL;
}

#ifdef DPDK_NETDEV
BUILD_ASSERT_DECL(offsetof(struct dp_packet, mbuf) == 0);

static inline const struct rte_mbuf *
dp_packet_mbuf_from_offset(const struct dp_packet *b, size_t *offset) {
    const struct rte_mbuf *mbuf = &b->mbuf;
    while (mbuf && *offset >= mbuf->data_len) {
        *offset -= mbuf->data_len;

        mbuf = mbuf->next;
    }

    return mbuf;
}

static inline bool
dp_packet_equal(const struct dp_packet *a, const struct dp_packet *b)
{
    if (dp_packet_size(a) != dp_packet_size(b)) {
        return false;
    }

    const struct rte_mbuf *m_a = NULL;
    const struct rte_mbuf *m_b = NULL;
    size_t abs_off_a = 0;
    size_t abs_off_b = 0;
    size_t len = 0;
    while (m_a != NULL && m_b != NULL) {
        size_t rel_off_a = abs_off_a;
        size_t rel_off_b = abs_off_b;
        m_a = dp_packet_mbuf_from_offset(a, &rel_off_a);
        m_b = dp_packet_mbuf_from_offset(b, &rel_off_b);
        if (!m_a || !m_b) {
            break;
        }

        len = MIN(m_a->data_len - rel_off_a, m_b->data_len - rel_off_b);

        if (memcmp(rte_pktmbuf_mtod_offset(m_a, char *, rel_off_a),
                   rte_pktmbuf_mtod_offset(m_b, char *, rel_off_b),
                   len)) {
            return false;
        }

        abs_off_a += len;
        abs_off_b += len;
    }

    return (!m_a && !m_b) ? true : false;
}

static inline void *
dp_packet_base(const struct dp_packet *b)
{
    return b->mbuf.buf_addr;
}

static inline void
dp_packet_set_base(struct dp_packet *b, void *d)
{
    b->mbuf.buf_addr = d;
}

static inline uint32_t
dp_packet_size(const struct dp_packet *b)
{
    return b->mbuf.pkt_len;
}

/* Sets the size of the packet 'b' to 'v'. For non-DPDK packets this only means
 * setting b->size_, but if used in a DPDK packet it means adjusting the first
 * mbuf pkt_len and last mbuf data_len, to reflect the real size, which can
 * lead to free'ing tail mbufs that are no longer used.
 *
 * This function should be used for setting the size only, and if there's an
 * assumption that the tail end of 'b' will be trimmed. For adjusting the head
 * 'end' of 'b', dp_packet_pull() should be used instead. */
static inline void
dp_packet_set_size(struct dp_packet *b, uint32_t v)
{
    if (b->source == DPBUF_DPDK) {
        struct rte_mbuf *mbuf = &b->mbuf;
        uint16_t new_len = v;
        uint16_t data_len;
        uint16_t nb_segs = 0;
        uint16_t pkt_len = 0;

        /* Trim 'v' length bytes from the end of the chained buffers, freeing
         * any buffers that may be left floating.
         *
         * For that traverse over the entire mbuf chain and, for each mbuf,
         * subtract its 'data_len' from 'new_len' (initially set to 'v'), which
         * essentially spreads 'new_len' between all existing mbufs in the
         * chain. While traversing the mbuf chain, we end the traversal if:
         * - 'new_size' reaches 0, meaning the passed 'v' has been
         *   appropriately spread over the mbuf chain. The remaining mbufs are
         *   freed;
         * - We reach the last mbuf in the chain, in which case we set the last
         *   mbuf's 'data_len' to the minimum value between the current
         *   'new_len' (what's leftover from 'v') size and the maximum data the
         *   mbuf can hold (mbuf->buf_len - mbuf->data_off).
         *
         * The above formula will thus make sure that when a 'v' is smaller
         * than the overall 'pkt_len' (sum of all 'data_len'), it sets the new
         * size and frees the leftover mbufs. In the other hand, if 'v' is
         * bigger, it sets the size to the maximum available space, but no more
         * than that. */
        while (mbuf) {
            data_len = MIN(new_len, mbuf->data_len);
            mbuf->data_len = data_len;

            if (new_len - data_len <= 0) {
                /* Free the rest of chained mbufs */
                free_dpdk_buf(CONTAINER_OF(mbuf->next, struct dp_packet,
                                           mbuf));
                mbuf->next = NULL;
            } else if (!mbuf->next) {
                /* Don't assign more than what we have available */
                mbuf->data_len = MIN(new_len,
                                     mbuf->buf_len - mbuf->data_off);
            }

            new_len -= data_len;
            nb_segs += 1;
            pkt_len += mbuf->data_len;
            mbuf = mbuf->next;
        }

        /* pkt_len != v would effectively mean that pkt_len < than 'v' (as
         * being bigger is logically impossible). Being < than 'v' would mean
         * the 'v' provided was bigger than the available room, which is the
         * responsibility of the caller to make sure there is enough room */
        ovs_assert(pkt_len == v);

        b->mbuf.nb_segs = nb_segs;
        b->mbuf.pkt_len = pkt_len;
    } else {
        b->mbuf.data_len = v;
        /* Total length of all segments linked to this segment. */
        b->mbuf.pkt_len = v;
    }
}

static inline uint16_t
__packet_data(const struct dp_packet *b)
{
    return b->mbuf.data_off;
}

static inline void
__packet_set_data(struct dp_packet *b, uint16_t v)
{
    if (b->source == DPBUF_DPDK) {
        /* Moving data_off away from the first mbuf in the chain is not a
         * possibility using DPBUF_DPDK dp_packets */
        ovs_assert(v == UINT16_MAX || v <= b->mbuf.buf_len);

        uint16_t prev_ofs = b->mbuf.data_off;
        b->mbuf.data_off = v;
        int16_t ofs_diff = prev_ofs - b->mbuf.data_off;

        /* When dealing with DPDK mbufs, keep data_off and data_len in sync.
         * Thus, update data_len if the length changes with the move of
         * data_off. However, if data_len is 0, there's no data to move and
         * data_len should remain 0. */

        if (b->mbuf.data_len != 0) {
            b->mbuf.data_len += ofs_diff;
        }
    } else {
        b->mbuf.data_off = v;
    }
}

static inline uint16_t
dp_packet_get_allocated(const struct dp_packet *b)
{
    return b->mbuf.nb_segs * b->mbuf.buf_len;
}

static inline void
dp_packet_set_allocated(struct dp_packet *b, uint16_t s)
{
    b->mbuf.buf_len = s;
}

static inline void
dp_packet_copy_mbuf_flags(struct dp_packet *dst, const struct dp_packet *src)
{
    ovs_assert(dst != NULL && src != NULL);
    struct rte_mbuf *buf_dst = &dst->mbuf;
    const struct rte_mbuf *buf_src = &src->mbuf;

    buf_dst->ol_flags = buf_src->ol_flags;
    buf_dst->packet_type = buf_src->packet_type;
    buf_dst->tx_offload = buf_src->tx_offload;
}

/* Returns the RSS hash of the packet 'p'.  Note that the returned value is
 * correct only if 'dp_packet_rss_valid(p)' returns true */
static inline uint32_t
dp_packet_get_rss_hash(struct dp_packet *p)
{
    return p->mbuf.hash.rss;
}

static inline void
dp_packet_set_rss_hash(struct dp_packet *p, uint32_t hash)
{
    p->mbuf.hash.rss = hash;
    p->mbuf.ol_flags |= PKT_RX_RSS_HASH;
}

static inline bool
dp_packet_rss_valid(struct dp_packet *p)
{
    return p->mbuf.ol_flags & PKT_RX_RSS_HASH;
}

static inline void
dp_packet_rss_invalidate(struct dp_packet *p OVS_UNUSED)
{
}

static inline void
dp_packet_mbuf_rss_flag_reset(struct dp_packet *p)
{
    p->mbuf.ol_flags &= ~PKT_RX_RSS_HASH;
}

/* This initialization is needed for packets that do not come from DPDK
 * interfaces, when vswitchd is built with --with-dpdk. */
static inline void
dp_packet_mbuf_init(struct dp_packet *p)
{
    p->mbuf.ol_flags = p->mbuf.tx_offload = p->mbuf.packet_type = 0;
    p->mbuf.nb_segs = 1;
    p->mbuf.next = NULL;
    p->mstate = NULL;
}

static inline bool
dp_packet_ip_checksum_valid(struct dp_packet *p)
{
    return (p->mbuf.ol_flags & PKT_RX_IP_CKSUM_MASK) ==
            PKT_RX_IP_CKSUM_GOOD;
}

static inline bool
dp_packet_ip_checksum_bad(struct dp_packet *p)
{
    return (p->mbuf.ol_flags & PKT_RX_IP_CKSUM_MASK) ==
            PKT_RX_IP_CKSUM_BAD;
}

static inline bool
dp_packet_l4_checksum_valid(struct dp_packet *p)
{
    return (p->mbuf.ol_flags & PKT_RX_L4_CKSUM_MASK) ==
            PKT_RX_L4_CKSUM_GOOD;
}

static inline bool
dp_packet_l4_checksum_bad(struct dp_packet *p)
{
    return (p->mbuf.ol_flags & PKT_RX_L4_CKSUM_MASK) ==
            PKT_RX_L4_CKSUM_BAD;
}

static inline void
reset_dp_packet_checksum_ol_flags(struct dp_packet *p)
{
    p->mbuf.ol_flags &= ~(PKT_RX_L4_CKSUM_GOOD | PKT_RX_L4_CKSUM_BAD |
                          PKT_RX_IP_CKSUM_GOOD | PKT_RX_IP_CKSUM_BAD);
}

static inline bool
dp_packet_has_flow_mark(struct dp_packet *p, uint32_t *mark)
{
    if (p->mbuf.ol_flags & PKT_RX_FDIR_ID) {
        *mark = p->mbuf.hash.fdir.hi;
        return true;
    }

    return false;
}

static inline void
dp_packet_copy_from_offset(const struct dp_packet *b, size_t offset,
                           size_t size, void *buf) {
    if (dp_packet_is_linear(b)) {
        memcpy(buf, (char *)dp_packet_data(b) + offset, size);
    } else {
        const struct rte_mbuf *mbuf = dp_packet_mbuf_from_offset(b, &offset);
        rte_pktmbuf_read(mbuf, offset, size, buf);
    }
}

static inline bool
dp_packet_is_linear(const struct dp_packet *b)
{
    if (b->source == DPBUF_DPDK) {
        return rte_pktmbuf_is_contiguous(&b->mbuf);
    }

    return true;
}

/* Linearizes the data on packet 'b', by copying the data into system's memory.
 * After this the packet is effectively a DPBUF_MALLOC packet. The caller is
 * responsible * for ensuring 'b' needs linearization, by calling
 * dp_packet_is_linear().
 *
 * This is an expensive operation which should only be performed as a last
 * resort, when multi-segments are under use but data must be accessed
 * linearly. */
static inline void
dp_packet_linearize(struct dp_packet *b)
{
    struct rte_mbuf *mbuf = CONST_CAST(struct rte_mbuf *, &b->mbuf);
    struct dp_packet *pkt = CONST_CAST(struct dp_packet *, b);
    uint32_t pkt_len = dp_packet_size(pkt);
    struct mbuf_state *mstate = NULL;
    void *dst = xmalloc(pkt_len);

    /* Copy packet's data to system's memory */
    if (!rte_pktmbuf_read(mbuf, 0, pkt_len, dst)) {
        return;
    }

    /* Free all mbufs except for the first */
    dp_packet_clear(pkt);

    /* Save mbuf's buf_addr to restore later */
    mstate = xmalloc(sizeof(*mstate));
    mstate->addr = pkt->mbuf.buf_addr;
    mstate->len = pkt->mbuf.buf_len;
    mstate->off = pkt->mbuf.data_off;
    pkt->mstate = mstate;

    /* Tranform DPBUF_DPDK packet into a DPBUF_MALLOC packet */
    pkt->source = DPBUF_MALLOC;
    pkt->mbuf.buf_addr = dst;
    pkt->mbuf.buf_len = pkt_len;
    pkt->mbuf.data_off = 0;
    dp_packet_set_size(pkt, pkt_len);
}
#else /* DPDK_NETDEV */
static inline bool
dp_packet_equal(const struct dp_packet *a, const struct dp_packet *b)
{
    return dp_packet_size(a) == dp_packet_size(b) &&
           !memcmp(dp_packet_data(a), dp_packet_data(b), dp_packet_size(a));
}

static inline void *
dp_packet_base(const struct dp_packet *b)
{
    return b->base_;
}

static inline void
dp_packet_set_base(struct dp_packet *b, void *d)
{
    b->base_ = d;
}

static inline uint32_t
dp_packet_size(const struct dp_packet *b)
{
    return b->size_;
}

static inline void
dp_packet_set_size(struct dp_packet *b, uint32_t v)
{
    b->size_ = v;
}

static inline uint16_t
__packet_data(const struct dp_packet *b)
{
    return b->data_ofs;
}

static inline void
__packet_set_data(struct dp_packet *b, uint16_t v)
{
    b->data_ofs = v;
}

static inline uint16_t
dp_packet_get_allocated(const struct dp_packet *b)
{
    return b->allocated_;
}

static inline void
dp_packet_set_allocated(struct dp_packet *b, uint16_t s)
{
    b->allocated_ = s;
}

/* Returns the RSS hash of the packet 'p'.  Note that the returned value is
 * correct only if 'dp_packet_rss_valid(p)' returns true */
static inline uint32_t
dp_packet_get_rss_hash(struct dp_packet *p)
{
    return p->rss_hash;
}

static inline void
dp_packet_set_rss_hash(struct dp_packet *p, uint32_t hash)
{
    p->rss_hash = hash;
    p->rss_hash_valid = true;
}

static inline bool
dp_packet_rss_valid(struct dp_packet *p)
{
    return p->rss_hash_valid;
}

static inline void
dp_packet_rss_invalidate(struct dp_packet *p)
{
    p->rss_hash_valid = false;
}

static inline void
dp_packet_mbuf_rss_flag_reset(struct dp_packet *p OVS_UNUSED)
{
}

static inline void
dp_packet_mbuf_init(struct dp_packet *p OVS_UNUSED)
{
}

static inline bool
dp_packet_ip_checksum_valid(struct dp_packet *p OVS_UNUSED)
{
    return false;
}

static inline bool
dp_packet_ip_checksum_bad(struct dp_packet *p OVS_UNUSED)
{
    return false;
}

static inline bool
dp_packet_l4_checksum_valid(struct dp_packet *p OVS_UNUSED)
{
    return false;
}

static inline bool
dp_packet_l4_checksum_bad(struct dp_packet *p OVS_UNUSED)
{
    return false;
}

static inline void
reset_dp_packet_checksum_ol_flags(struct dp_packet *p OVS_UNUSED)
{
}

static inline bool
dp_packet_has_flow_mark(struct dp_packet *p OVS_UNUSED,
                        uint32_t *mark OVS_UNUSED)
{
    return false;
}

static inline void
dp_packet_copy_from_offset(const struct dp_packet *b, size_t offset,
                           size_t size, void *buf)
{
    memcpy(buf, (char *)dp_packet_data(b) + offset, size);
}

static inline bool
dp_packet_is_linear(const struct dp_packet *b OVS_UNUSED)
{
    return true;
}

static inline void
dp_packet_linearize(struct dp_packet *b OVS_UNUSED)
{
}
#endif /* DPDK_NETDEV */

static inline void
dp_packet_reset_cutlen(struct dp_packet *b)
{
    b->cutlen = 0;
}

static inline uint32_t
dp_packet_set_cutlen(struct dp_packet *b, uint32_t max_len)
{
    if (max_len < ETH_HEADER_LEN) {
        max_len = ETH_HEADER_LEN;
    }

    if (max_len >= dp_packet_size(b)) {
        b->cutlen = 0;
    } else {
        b->cutlen = dp_packet_size(b) - max_len;
    }
    return b->cutlen;
}

static inline uint32_t
dp_packet_get_cutlen(const struct dp_packet *b)
{
    /* Always in valid range if user uses dp_packet_set_cutlen. */
    return b->cutlen;
}

static inline uint32_t
dp_packet_get_send_len(const struct dp_packet *b)
{
    return dp_packet_size(b) - dp_packet_get_cutlen(b);
}

static inline void *
dp_packet_data(const struct dp_packet *b)
{
    return __packet_data(b) != UINT16_MAX
           ? (char *) dp_packet_base(b) + __packet_data(b) : NULL;
}

static inline void
dp_packet_set_data(struct dp_packet *b, void *data)
{
    if (data) {
        __packet_set_data(b, (char *) data - (char *) dp_packet_base(b));
    } else {
        __packet_set_data(b, UINT16_MAX);
    }
}

static inline void
dp_packet_reset_packet(struct dp_packet *b, size_t off)
{
    dp_packet_try_pull(b, off);
    dp_packet_reset_offsets(b);
}

enum { NETDEV_MAX_BURST = 32 }; /* Maximum number packets in a batch. */

struct dp_packet_batch {
    size_t count;
    bool trunc; /* true if the batch needs truncate. */
    struct dp_packet *packets[NETDEV_MAX_BURST];
};

static inline void
dp_packet_batch_init(struct dp_packet_batch *batch)
{
    batch->count = 0;
    batch->trunc = false;
}

static inline void
dp_packet_batch_add__(struct dp_packet_batch *batch,
                      struct dp_packet *packet, size_t limit)
{
    if (batch->count < limit) {
        batch->packets[batch->count++] = packet;
    } else {
        dp_packet_delete(packet);
    }
}

/* When the batch is full, 'packet' will be dropped and freed. */
static inline void
dp_packet_batch_add(struct dp_packet_batch *batch, struct dp_packet *packet)
{
    dp_packet_batch_add__(batch, packet, NETDEV_MAX_BURST);
}

static inline size_t
dp_packet_batch_size(const struct dp_packet_batch *batch)
{
    return batch->count;
}

/* Clear 'batch' for refill. Use dp_packet_batch_refill() to add
 * packets back into the 'batch'. */
static inline void
dp_packet_batch_refill_init(struct dp_packet_batch *batch)
{
    batch->count = 0;
};

static inline void
dp_packet_batch_refill(struct dp_packet_batch *batch,
                       struct dp_packet *packet, size_t idx)
{
    dp_packet_batch_add__(batch, packet, MIN(NETDEV_MAX_BURST, idx + 1));
}

static inline void
dp_packet_batch_init_packet(struct dp_packet_batch *batch, struct dp_packet *p)
{
    dp_packet_batch_init(batch);
    batch->count = 1;
    batch->packets[0] = p;
}

static inline bool
dp_packet_batch_is_empty(const struct dp_packet_batch *batch)
{
    return !dp_packet_batch_size(batch);
}

#define DP_PACKET_BATCH_FOR_EACH(IDX, PACKET, BATCH)                \
    for (size_t IDX = 0; IDX < dp_packet_batch_size(BATCH); IDX++)  \
        if (PACKET = BATCH->packets[IDX], true)

/* Use this macro for cases where some packets in the 'BATCH' may be
 * dropped after going through each packet in the 'BATCH'.
 *
 * For packets to stay in the 'BATCH', they need to be refilled back
 * into the 'BATCH' by calling dp_packet_batch_refill(). Caller owns
 * the packets that are not refilled.
 *
 * Caller needs to supply 'SIZE', that stores the current number of
 * packets in 'BATCH'. It is best to declare this variable with
 * the 'const' modifier since it should not be modified by
 * the iterator.  */
#define DP_PACKET_BATCH_REFILL_FOR_EACH(IDX, SIZE, PACKET, BATCH)       \
    for (dp_packet_batch_refill_init(BATCH), IDX=0; IDX < SIZE; IDX++)  \
         if (PACKET = BATCH->packets[IDX], true)

static inline void
dp_packet_batch_clone(struct dp_packet_batch *dst,
                      struct dp_packet_batch *src)
{
    struct dp_packet *packet;

    dp_packet_batch_init(dst);
    DP_PACKET_BATCH_FOR_EACH (i, packet, src) {
        dp_packet_batch_add(dst, dp_packet_clone(packet));
    }
    dst->trunc = src->trunc;
}

static inline void
dp_packet_delete_batch(struct dp_packet_batch *batch, bool should_steal)
{
    if (should_steal) {
        struct dp_packet *packet;

        DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
            dp_packet_delete(packet);
        }
        dp_packet_batch_init(batch);
    }
}

static inline void
dp_packet_batch_init_packet_fields(struct dp_packet_batch *batch)
{
    struct dp_packet *packet;

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        dp_packet_reset_cutlen(packet);
        packet->packet_type = htonl(PT_ETH);
    }
}

static inline void
dp_packet_batch_apply_cutlen(struct dp_packet_batch *batch)
{
    if (batch->trunc) {
        struct dp_packet *packet;

        DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
            dp_packet_set_size(packet, dp_packet_get_send_len(packet));
            dp_packet_reset_cutlen(packet);
        }
        batch->trunc = false;
    }
}

static inline void
dp_packet_batch_reset_cutlen(struct dp_packet_batch *batch)
{
    if (batch->trunc) {
        struct dp_packet *packet;

        DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
            dp_packet_reset_cutlen(packet);
        }
        batch->trunc = false;
    }
}

#ifdef  __cplusplus
}
#endif

#endif /* dp-packet.h */
