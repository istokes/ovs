/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2016 Nicira, Inc.
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
#include <stdlib.h>
#include <string.h>

#include "dp-packet.h"
#include "netdev-dpdk.h"
#include "openvswitch/dynamic-string.h"
#include "util.h"

#ifdef DPDK_NETDEV
#define MBUF_BUF_END(BUF_ADDR, BUF_LEN) \
    (char *) (((char *) BUF_ADDR) + BUF_LEN)
#endif

static void
dp_packet_init__(struct dp_packet *b, size_t allocated, enum dp_packet_source source)
{
    dp_packet_set_allocated(b, allocated);
    b->source = source;
    dp_packet_reset_offsets(b);
    pkt_metadata_init(&b->md, 0);
    dp_packet_rss_invalidate(b);
    dp_packet_mbuf_init(b);
    dp_packet_reset_cutlen(b);
    /* By default assume the packet type to be Ethernet. */
    b->packet_type = htonl(PT_ETH);
}

static void
dp_packet_use__(struct dp_packet *b, void *base, size_t allocated,
             enum dp_packet_source source)
{
    dp_packet_init__(b, allocated, source);

    dp_packet_set_base(b, base);
    dp_packet_set_data(b, base);
    dp_packet_set_size(b, 0);
}

/* Initializes 'b' as an empty dp_packet that contains the 'allocated' bytes of
 * memory starting at 'base'.  'base' should be the first byte of a region
 * obtained from malloc().  It will be freed (with free()) if 'b' is resized or
 * freed. */
void
dp_packet_use(struct dp_packet *b, void *base, size_t allocated)
{
    dp_packet_use__(b, base, allocated, DPBUF_MALLOC);
}

/* Initializes 'b' as an empty dp_packet that contains the 'allocated' bytes of
 * memory starting at 'base'.  'base' should point to a buffer on the stack.
 * (Nothing actually relies on 'base' being allocated on the stack.  It could
 * be static or malloc()'d memory.  But stack space is the most common use
 * case.)
 *
 * 'base' should be appropriately aligned.  Using an array of uint32_t or
 * uint64_t for the buffer is a reasonable way to ensure appropriate alignment
 * for 32- or 64-bit data.
 *
 * An dp_packet operation that requires reallocating data will copy the provided
 * buffer into a malloc()'d buffer.  Thus, it is wise to call dp_packet_uninit()
 * on an dp_packet initialized by this function, so that if it expanded into the
 * heap, that memory is freed. */
void
dp_packet_use_stub(struct dp_packet *b, void *base, size_t allocated)
{
    dp_packet_use__(b, base, allocated, DPBUF_STUB);
}

/* Initializes 'b' as an dp_packet whose data starts at 'data' and continues for
 * 'size' bytes.  This is appropriate for an dp_packet that will be used to
 * inspect existing data, without moving it around or reallocating it, and
 * generally without modifying it at all.
 *
 * An dp_packet operation that requires reallocating data will assert-fail if this
 * function was used to initialize it. */
void
dp_packet_use_const(struct dp_packet *b, const void *data, size_t size)
{
    dp_packet_use__(b, CONST_CAST(void *, data), size, DPBUF_STACK);
    dp_packet_set_size(b, size);
}

/* Initializes 'b' as a DPDK dp-packet, which must have been allocated from a
 * DPDK memory pool. */
void
dp_packet_init_dpdk(struct dp_packet *b)
{
    b->source = DPBUF_DPDK;
#ifdef DPDK_NETDEV
    b->mstate = NULL;
#endif
}

/* Initializes 'b' as an empty dp_packet with an initial capacity of 'size'
 * bytes. */
void
dp_packet_init(struct dp_packet *b, size_t size)
{
    dp_packet_use(b, size ? xmalloc(size) : NULL, size);
}

/* Frees memory that 'b' points to. */
void
dp_packet_uninit(struct dp_packet *b)
{
    if (b) {
        if (b->source == DPBUF_MALLOC) {
            free(dp_packet_base(b));

#ifdef DPDK_NETDEV
            /* Packet has been "linearized" */
            if (b->mstate) {
                b->source = DPBUF_DPDK;
                b->mbuf.buf_addr = b->mstate->addr;
                b->mbuf.buf_len = b->mstate->len;
                b->mbuf.data_off = b->mstate->off;

                free(b->mstate);
                b->mstate = NULL;

                free_dpdk_buf((struct dp_packet *) b);
            }
#endif
        } else if (b->source == DPBUF_DPDK) {
#ifdef DPDK_NETDEV
            /* If this dp_packet was allocated by DPDK it must have been
             * created as a dp_packet */
            free_dpdk_buf((struct dp_packet*) b);
#endif
        }
    }
}

/* Creates and returns a new dp_packet with an initial capacity of 'size'
 * bytes. */
struct dp_packet *
dp_packet_new(size_t size)
{
    struct dp_packet *b = xmalloc(sizeof *b);
    dp_packet_init(b, size);
    return b;
}

/* Creates and returns a new dp_packet with an initial capacity of 'size +
 * headroom' bytes, reserving the first 'headroom' bytes as headroom. */
struct dp_packet *
dp_packet_new_with_headroom(size_t size, size_t headroom)
{
    struct dp_packet *b = dp_packet_new(size + headroom);
    dp_packet_reserve(b, headroom);
    return b;
}

/* Creates and returns a new dp_packet that initially contains a copy of the
 * 'dp_packet_size(buffer)' bytes of data starting at 'buffer->data' with no headroom or
 * tailroom. */
struct dp_packet *
dp_packet_clone(const struct dp_packet *buffer)
{
    return dp_packet_clone_with_headroom(buffer, 0);
}

#ifdef DPDK_NETDEV
struct dp_packet *
dp_packet_clone_with_headroom(const struct dp_packet *b, size_t headroom) {
    struct dp_packet *new_buffer;
    uint32_t pkt_len = dp_packet_size(b);

    /* Copy multi-seg data. */
    if (b->source == DPBUF_DPDK && !rte_pktmbuf_is_contiguous(&b->mbuf)) {
        void *dst = NULL;
        struct rte_mbuf *mbuf = CONST_CAST(struct rte_mbuf *, &b->mbuf);

        new_buffer = dp_packet_new_with_headroom(pkt_len, headroom);
        dst = dp_packet_data(new_buffer);
        dp_packet_set_size(new_buffer, pkt_len);

        if (!rte_pktmbuf_read(mbuf, 0, pkt_len, dst)) {
            dp_packet_delete(new_buffer);
            return NULL;
        }
    } else {
        new_buffer = dp_packet_clone_data_with_headroom(dp_packet_data(b),
                                                        dp_packet_size(b),
                                                        headroom);
    }

    dp_packet_copy_common_members(new_buffer, b);

    dp_packet_copy_mbuf_flags(new_buffer, b);
    if (dp_packet_rss_valid(new_buffer)) {
        new_buffer->mbuf.hash.rss = b->mbuf.hash.rss;
    }

    return new_buffer;
}
#else
/* Creates and returns a new dp_packet whose data are copied from 'buffer'.
 * The returned dp_packet will additionally have 'headroom' bytes of
 * headroom. */
struct dp_packet *
dp_packet_clone_with_headroom(const struct dp_packet *b, size_t headroom)
{
    struct dp_packet *new_buffer;
    uint32_t pkt_len = dp_packet_size(b);

    new_buffer = dp_packet_clone_data_with_headroom(dp_packet_data(b),
                                                    pkt_len, headroom);

    dp_packet_copy_common_members(new_buffer, b);

    new_buffer->rss_hash_valid = b->rss_hash_valid;
    if (dp_packet_rss_valid(new_buffer)) {
        new_buffer->rss_hash = b->rss_hash;
    }

    return new_buffer;
}
#endif

/* Creates and returns a new dp_packet that initially contains a copy of the
 * 'size' bytes of data starting at 'data' with no headroom or tailroom. */
struct dp_packet *
dp_packet_clone_data(const void *data, size_t size)
{
    return dp_packet_clone_data_with_headroom(data, size, 0);
}

/* Creates and returns a new dp_packet that initially contains 'headroom' bytes of
 * headroom followed by a copy of the 'size' bytes of data starting at
 * 'data'. */
struct dp_packet *
dp_packet_clone_data_with_headroom(const void *data, size_t size, size_t headroom)
{
    struct dp_packet *b = dp_packet_new_with_headroom(size, headroom);
    dp_packet_put(b, data, size);
    return b;
}

static void
dp_packet_copy__(struct dp_packet *b, uint8_t *new_base,
              size_t new_headroom, size_t new_tailroom)
{
    const uint8_t *old_base = dp_packet_base(b);
    size_t old_headroom = dp_packet_headroom(b);
    size_t old_tailroom = dp_packet_tailroom(b);
    size_t copy_headroom = MIN(old_headroom, new_headroom);
    size_t copy_tailroom = MIN(old_tailroom, new_tailroom);

    memcpy(&new_base[new_headroom - copy_headroom],
           &old_base[old_headroom - copy_headroom],
           copy_headroom + dp_packet_size(b) + copy_tailroom);
}

/* Reallocates 'b' so that it has exactly 'new_headroom' and 'new_tailroom'
 * bytes of headroom and tailroom, respectively. */
static void
dp_packet_resize__(struct dp_packet *b, size_t new_headroom, size_t new_tailroom)
{
    void *new_base, *new_data;
    size_t new_allocated;

    new_allocated = new_headroom + dp_packet_size(b) + new_tailroom;

    switch (b->source) {
    case DPBUF_DPDK:
        OVS_NOT_REACHED();

    case DPBUF_MALLOC:
        if (new_headroom == dp_packet_headroom(b)) {
            new_base = xrealloc(dp_packet_base(b), new_allocated);
        } else {
            new_base = xmalloc(new_allocated);
            dp_packet_copy__(b, new_base, new_headroom, new_tailroom);
            free(dp_packet_base(b));
        }
        break;

    case DPBUF_STACK:
        OVS_NOT_REACHED();

    case DPBUF_STUB:
        b->source = DPBUF_MALLOC;
        new_base = xmalloc(new_allocated);
        dp_packet_copy__(b, new_base, new_headroom, new_tailroom);
        break;

    default:
        OVS_NOT_REACHED();
    }

    dp_packet_set_allocated(b, new_allocated);
    dp_packet_set_base(b, new_base);

    new_data = (char *) new_base + new_headroom;
    if (dp_packet_data(b) != new_data) {
        dp_packet_set_data(b, new_data);
    }
}

/* Ensures that 'b' has room for at least 'size' bytes at its tail end,
 * reallocating and copying its data if necessary.  Its headroom, if any, is
 * preserved. */
void
dp_packet_prealloc_tailroom(struct dp_packet *b, size_t size)
{
    if (size > dp_packet_tailroom(b)) {
        dp_packet_resize__(b, dp_packet_headroom(b), MAX(size, 64));
    }
}

/* Ensures that 'b' has room for at least 'size' bytes at its head,
 * reallocating and copying its data if necessary.  Its tailroom, if any, is
 * preserved. */
void
dp_packet_prealloc_headroom(struct dp_packet *b, size_t size)
{
    if (size > dp_packet_headroom(b)) {
        dp_packet_resize__(b, MAX(size, 64), dp_packet_tailroom(b));
    }
}

#ifdef DPDK_NETDEV
/* Write len data bytes in a mbuf at specified offset.
 *
 * 'mbuf', pointer to the destination mbuf where 'ofs' is, and the mbuf where
 * the data will first be written.
 * 'ofs', the offset within the provided 'mbuf' where 'data' is to be written.
 * 'len', the size of the to be written 'data'.
 * 'data', pointer to the to be written bytes.
 *
 * Note: This function is the counterpart of the `rte_pktmbuf_read()` function
 * available with DPDK, in the rte_mbuf.h */
void
dp_packet_mbuf_write(struct rte_mbuf *mbuf, int16_t ofs, uint32_t len,
                     const void *data)
{
    char *dst_addr;
    uint16_t data_len;
    int len_copy;
    while (mbuf) {
        if (len == 0) {
            break;
        }

        dst_addr = rte_pktmbuf_mtod_offset(mbuf, char *, ofs);
        data_len = MBUF_BUF_END(mbuf->buf_addr, mbuf->buf_len) - dst_addr;

        len_copy = MIN(len, data_len);
        /* We don't know if 'data' is the result of a rte_pktmbuf_read() call,
         * in which case we may end up writing to the same region of memory we
         * are reading from and overlapping. Hence the use of memmove() here */
        memmove(dst_addr, data, len_copy);

        data = ((char *) data) + len_copy;
        len -= len_copy;
        ofs = 0;

        mbuf->data_len = len_copy;
        mbuf = mbuf->next;
    }
}

static void
dp_packet_mbuf_shift_(struct rte_mbuf *dbuf, int16_t dst_ofs,
                      const struct rte_mbuf *sbuf, uint16_t src_ofs, int len)
{
    char *rd = xmalloc(sizeof(*rd) * len);
    const char *wd = rte_pktmbuf_read(sbuf, src_ofs, len, rd);

    ovs_assert(wd);

    dp_packet_mbuf_write(dbuf, dst_ofs, len, wd);

    free(rd);
}

/* Similarly to dp_packet_shift(), shifts the data within the mbufs of a
 * dp_packet of DPBUF_DPDK source by 'delta' bytes.
 * Caller must make sure of the following conditions:
 * - When shifting left, delta can't be bigger than the data_len available in
 *   the last mbuf;
 * - When shifting right, delta can't be bigger than the space available in the
 *   first mbuf (buf_len - data_off).
 * Both these conditions guarantee that a shift operation doesn't fall outside
 * the bounds of the existing mbufs, so that the first and last mbufs (when
 * using multi-segment mbufs), remain the same. */
static void
dp_packet_mbuf_shift(struct dp_packet *b, int delta)
{
    uint16_t src_ofs;
    int16_t dst_ofs;

    struct rte_mbuf *mbuf = CONST_CAST(struct rte_mbuf *, &b->mbuf);
    struct rte_mbuf *tmbuf = rte_pktmbuf_lastseg(mbuf);

    if (delta < 0) {
        ovs_assert(-delta <= tmbuf->data_len);
    } else {
        ovs_assert(delta < (mbuf->buf_len - mbuf->data_off));
    }

    /* Set the destination and source offsets to copy to */
    dst_ofs = delta;
    src_ofs = 0;

    /* Shift data from src mbuf and offset to dst mbuf and offset */
    dp_packet_mbuf_shift_(mbuf, dst_ofs, mbuf, src_ofs,
                          rte_pktmbuf_pkt_len(mbuf));

    /* Update mbufs' properties, and if using multi-segment mbufs, first and
     * last mbuf's data_len also needs to be adjusted */
    mbuf->data_off = mbuf->data_off + dst_ofs;
}
#endif

/* Shifts all of the data within the allocated space in 'b' by 'delta' bytes.
 * For example, a 'delta' of 1 would cause each byte of data to move one byte
 * forward (from address 'p' to 'p+1'), and a 'delta' of -1 would cause each
 * byte to move one byte backward (from 'p' to 'p-1'). */
void
dp_packet_shift(struct dp_packet *b, int delta)
{
    ovs_assert(delta > 0 ? delta <= dp_packet_tailroom(b)
               : delta < 0 ? -delta <= dp_packet_headroom(b)
               : true);

    if (delta != 0) {
#ifdef DPDK_NETDEV
        if (b->source == DPBUF_DPDK) {
            dp_packet_mbuf_shift(b, delta);
            return;
        }
#endif
        char *dst = (char *) dp_packet_data(b) + delta;
        memmove(dst, dp_packet_data(b), dp_packet_size(b));
        dp_packet_set_data(b, dst);
    }
}

/* Appends 'size' bytes of data to the tail end of 'b', reallocating and
 * copying its data if necessary.  Returns a pointer to the first byte of the
 * new data, which is left uninitialized. */
void *
dp_packet_put_uninit(struct dp_packet *b, size_t size)
{
    void *p;
    dp_packet_prealloc_tailroom(b, size);
    p = dp_packet_tail(b);
    dp_packet_set_size(b, dp_packet_size(b) + size);
    return p;
}

/* Appends 'size' zeroed bytes to the tail end of 'b'.  Data in 'b' is
 * reallocated and copied if necessary.  Returns a pointer to the first byte of
 * the data's location in the dp_packet. */
void *
dp_packet_put_zeros(struct dp_packet *b, size_t size)
{
    void *dst = dp_packet_put_uninit(b, size);
    memset(dst, 0, size);
    return dst;
}

/* Appends the 'size' bytes of data in 'p' to the tail end of 'b'.  Data in 'b'
 * is reallocated and copied if necessary.  Returns a pointer to the first
 * byte of the data's location in the dp_packet. */
void *
dp_packet_put(struct dp_packet *b, const void *p, size_t size)
{
    void *dst = dp_packet_put_uninit(b, size);
    memcpy(dst, p, size);
    return dst;
}

/* Parses as many pairs of hex digits as possible (possibly separated by
 * spaces) from the beginning of 's', appending bytes for their values to 'b'.
 * Returns the first character of 's' that is not the first of a pair of hex
 * digits.  If 'n' is nonnull, stores the number of bytes added to 'b' in
 * '*n'. */
char *
dp_packet_put_hex(struct dp_packet *b, const char *s, size_t *n)
{
    size_t initial_size = dp_packet_size(b);
    for (;;) {
        uint8_t byte;
        bool ok;

        s += strspn(s, " \t\r\n");
        byte = hexits_value(s, 2, &ok);
        if (!ok) {
            if (n) {
                *n = dp_packet_size(b) - initial_size;
            }
            return CONST_CAST(char *, s);
        }

        dp_packet_put(b, &byte, 1);
        s += 2;
    }
}

/* Reserves 'size' bytes of headroom so that they can be later allocated with
 * dp_packet_push_uninit() without reallocating the dp_packet. */
void
dp_packet_reserve(struct dp_packet *b, size_t size)
{
    ovs_assert(!dp_packet_size(b));
    dp_packet_prealloc_tailroom(b, size);
    dp_packet_set_data(b, (char*)dp_packet_data(b) + size);
}

/* Reserves 'headroom' bytes at the head and 'tailroom' at the end so that
 * they can be later allocated with dp_packet_push_uninit() or
 * dp_packet_put_uninit() without reallocating the dp_packet. */
void
dp_packet_reserve_with_tailroom(struct dp_packet *b, size_t headroom,
                             size_t tailroom)
{
    ovs_assert(!dp_packet_size(b));
    dp_packet_prealloc_tailroom(b, headroom + tailroom);
    dp_packet_set_data(b, (char*)dp_packet_data(b) + headroom);
}

/* Prefixes 'size' bytes to the head end of 'b', reallocating and copying its
 * data if necessary.  Returns a pointer to the first byte of the data's
 * location in the dp_packet.  The new data is left uninitialized. */
void *
dp_packet_push_uninit(struct dp_packet *b, size_t size)
{
    dp_packet_prealloc_headroom(b, size);
    dp_packet_set_data(b, (char*)dp_packet_data(b) - size);
    dp_packet_set_size(b, dp_packet_size(b) + size);
    return dp_packet_data(b);
}

/* Prefixes 'size' zeroed bytes to the head end of 'b', reallocating and
 * copying its data if necessary.  Returns a pointer to the first byte of the
 * data's location in the dp_packet. */
void *
dp_packet_push_zeros(struct dp_packet *b, size_t size)
{
    void *dst = dp_packet_push_uninit(b, size);
    memset(dst, 0, size);
    return dst;
}

/* Copies the 'size' bytes starting at 'p' to the head end of 'b', reallocating
 * and copying its data if necessary.  Returns a pointer to the first byte of
 * the data's location in the dp_packet. */
void *
dp_packet_push(struct dp_packet *b, const void *p, size_t size)
{
    void *dst = dp_packet_push_uninit(b, size);
    memcpy(dst, p, size);
    return dst;
}

/* Returns the data in 'b' as a block of malloc()'d memory and frees the buffer
 * within 'b'.  (If 'b' itself was dynamically allocated, e.g. with
 * dp_packet_new(), then it should still be freed with, e.g., dp_packet_delete().) */
void *
dp_packet_steal_data(struct dp_packet *b)
{
    void *p;
    ovs_assert(b->source != DPBUF_DPDK);

    if (b->source == DPBUF_MALLOC && dp_packet_data(b) == dp_packet_base(b)) {
        p = dp_packet_data(b);
    } else {
        p = xmemdup(dp_packet_data(b), dp_packet_size(b));
        if (b->source == DPBUF_MALLOC) {
            free(dp_packet_base(b));
        }
    }
    dp_packet_set_base(b, NULL);
    dp_packet_set_data(b, NULL);
    return p;
}

static inline void
dp_packet_adjust_layer_offset(uint16_t *offset, int increment)
{
    if (*offset != UINT16_MAX) {
        *offset += increment;
    }
}

/* Adjust the size of the l2_5 portion of the dp_packet, updating the l2
 * pointer and the layer offsets.  The caller is responsible for
 * modifying the contents. */
void *
dp_packet_resize_l2_5(struct dp_packet *b, int increment)
{
    if (increment >= 0) {
        dp_packet_push_uninit(b, increment);
    } else {
        dp_packet_pull(b, -increment);
    }

    /* Adjust layer offsets after l2_5. */
    dp_packet_adjust_layer_offset(&b->l3_ofs, increment);
    dp_packet_adjust_layer_offset(&b->l4_ofs, increment);

    return dp_packet_data(b);
}

/* Adjust the size of the l2 portion of the dp_packet, updating the l2
 * pointer and the layer offsets.  The caller is responsible for
 * modifying the contents. */
void *
dp_packet_resize_l2(struct dp_packet *b, int increment)
{
    dp_packet_resize_l2_5(b, increment);
    dp_packet_adjust_layer_offset(&b->l2_5_ofs, increment);
    return dp_packet_data(b);
}
