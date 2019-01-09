..
      Copyright 2018, Red Hat, Inc.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

============
Jumbo Frames
============

.. versionadded:: 2.6.0

By default, DPDK ports are configured with standard Ethernet MTU (1500B). To
enable Jumbo Frames support for a DPDK port, change the Interface's
``mtu_request`` attribute to a sufficiently large value. For example, to add a
:doc:`DPDK physical port <phy>` with an MTU of 9000, run::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
          options:dpdk-devargs=0000:01:00.0 mtu_request=9000

Similarly, to change the MTU of an existing port to 6200, run::

    $ ovs-vsctl set Interface dpdk-p0 mtu_request=6200

Some additional configuration is needed to take advantage of jumbo frames with
:doc:`vHost User ports <vhost-user>`:

- *Mergeable buffers* must be enabled for vHost User ports, as demonstrated in
  the QEMU command line snippet below::

      -netdev type=vhost-user,id=mynet1,chardev=char0,vhostforce \
      -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,mrg_rxbuf=on

- Where virtio devices are bound to the Linux kernel driver in a guest
  environment (i.e. interfaces are not bound to an in-guest DPDK driver), the
  MTU of those logical network interfaces must also be increased to a
  sufficiently large value. This avoids segmentation of Jumbo Frames received
  in the guest. Note that 'MTU' refers to the length of the IP packet only, and
  not that of the entire frame.

  To calculate the exact MTU of a standard IPv4 frame, subtract the L2 header
  and CRC lengths (i.e. 18B) from the max supported frame size. So, to set the
  MTU for a 9018B Jumbo Frame::

      $ ip link set eth1 mtu 9000

When Jumbo Frames are enabled, the size of a DPDK port's mbuf segments are
increased, such that a full Jumbo Frame of a specific size may be accommodated
within a single mbuf segment.

Jumbo frame support has been validated against 9728B frames, which is the
largest frame size supported by Fortville NIC using the DPDK i40e driver, but
larger frames and other DPDK NIC drivers may be supported. These cases are
common for use cases involving East-West traffic only.

-------------------
Multi-segment mbufs
-------------------

Instead of increasing the size of mbufs within a mempool, such that each mbuf
within the pool is large enough to contain an entire jumbo frame of a
user-defined size, mbufs can be chained together instead. In this approach each
mbuf in the chain stores a portion of the jumbo frame, by default ~2K bytes,
irrespective of the user-requested MTU value. Since each mbuf in the chain is
termed a segment, this approach is named "multi-segment mbufs".

This approach may bring more flexibility in use cases where the maximum packet
length may be hard to guess. For example, in cases where packets originate from
sources marked for offload (such as TSO), each packet may be larger than the
MTU, and as such, when forwarding it to a DPDK port a single mbuf may not be
enough to hold all of the packet's data.

Multi-segment and single-segment mbufs are mutually exclusive, and the user
must decide on which approach to adopt on initialisation. If multi-segment
mbufs is to be enabled, it can be done so with the following command::

    $ ovs-vsctl set Open_vSwitch . other_config:dpdk-multi-seg-mbufs=true

Single-segment mbufs still remain the default when using OvS-DPDK, and the
above option `dpdk-multi-seg-mbufs` must be explicitly set to `true` if
multi-segment mbufs are to be used.

~~~~~~~~~~~~~~~~~
Performance notes
~~~~~~~~~~~~~~~~~

When using multi-segment mbufs some PMDs may not support vectorized Tx
functions, due to its non-contiguous nature. As a result this can hit
performance for smaller packet sizes. For example, on a setup sending 64B
packets at line rate, a decrease of ~20% has been observed. The performance
impact stops being noticeable for larger packet sizes, although the exact size
will depend on each PMD, and vary between architectures.

Tests performed with the i40e PMD driver only showed this limitation for 64B
packets, and the same rate was observed when comparing multi-segment mbufs and
single-segment mbuf for 128B packets. In other words, the 20% drop in
performance was not observed for packets >= 128B during this test case.

Because of this, multi-segment mbufs is not advised to be used with smaller
packet sizes, such as 64B.

Also, note that using multi-segment mbufs won't improve memory usage. For a
packet of 9000B, for example, which would be stored on a single mbuf when using
the single-segment approach, 5 mbufs (9000/2176) of 2176B would be needed to
store the same data using the multi-segment mbufs approach (refer to
:doc:`/topics/dpdk/memory` for examples).

~~~~~~~~~~~
Limitations
~~~~~~~~~~~

Because multi-segment mbufs store the data uncontiguously in memory, when used
across DPDK and non-DPDK ports, a performance drop is expected, as the mbufs'
content needs to be copied into a contiguous region in memory to be used by
operations such as write(). Exchanging traffic between DPDK ports (such as
vhost and physical ports) doesn't have this limitation, however.

Other operations may have a hit in performance as well, under the current
implementation. For example, operations that require a checksum to be performed
on the data, such as pushing / popping a VXLAN header, will also require a copy
of the data (if it hasn't been copied before), or when using the Userspace
connection tracker.

Finally, it is assumed that, when enabling the multi-segment mbufs, a packet
header falls within the first mbuf, which is 2K in size. This is required
because at the moment the miniflow extraction and setting of the layer headers
(l2_5, l3, l4) assumes contiguous access to memory.
